package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type Event struct {
	TsNs uint64

	Pid uint32
	Uid uint32

	Saddr uint32
	Daddr uint32

	Sport uint16
	Dport uint16

	Proto  uint8
	Evtype uint8

	Pad0 uint16 // padding to align next uint32

	StateOld uint32
	StateNew uint32

	Bytes       uint64
	Retransmits uint32

	Pad1 uint32 // padding so Comm lands correctly / total size matches C

	Comm [16]byte
}

type FlowKey struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Proto uint8
}

type FlowAgg struct {
	FirstMonoNs uint64 `json:"first_ts_ns"`
	LastMonoNs  uint64 `json:"last_ts_ns"`

	FirstEpochS float64 `json:"first_ts_s"`
	LastEpochS  float64 `json:"last_ts_s"`
	FlushEpochS float64 `json:"flush_ts_s"`

	Saddr uint32 `json:"saddr"`
	Daddr uint32 `json:"daddr"`
	Sport uint16 `json:"sport"`
	Dport uint16 `json:"dport"`
	Proto uint8  `json:"proto"`

	SaddrStr string `json:"saddr_str"`
	DaddrStr string `json:"daddr_str"`

	BytesSent    uint64 `json:"bytes_sent"`
	BytesRecv    uint64 `json:"bytes_recv"`
	Retransmits  uint32 `json:"retransmits"`
	StateChanges uint32 `json:"state_changes"`
	Samples      uint64 `json:"samples"`

	PidMode  uint32 `json:"pid_mode"`
	UidMode  uint32 `json:"uid_mode"`
	CommMode string `json:"comm_mode"`
}

type RawEventOut struct {
	TsMonoNs uint64  `json:"ts_ns"`
	TsEpochS float64 `json:"ts_s"`

	Pid  uint32 `json:"pid"`
	Uid  uint32 `json:"uid"`
	Comm string `json:"comm"`

	Saddr uint32 `json:"saddr"`
	Daddr uint32 `json:"daddr"`
	Sport uint16 `json:"sport"`
	Dport uint16 `json:"dport"`
	Proto uint8  `json:"proto"`

	SaddrStr string `json:"saddr_str"`
	DaddrStr string `json:"daddr_str"`

	Evtype   uint8  `json:"evtype"`
	StateOld uint32 `json:"state_old"`
	StateNew uint32 `json:"state_new"`

	Bytes       uint64 `json:"bytes"`
	Retransmits uint32 `json:"retransmits"`
}

func ntohl(u uint32) uint32 {
	return (u&0x000000FF)<<24 |
		(u&0x0000FF00)<<8 |
		(u&0x00FF0000)>>8 |
		(u&0xFF000000)>>24
}

func u32ToIPv4StrBE(u uint32) string {
	b := []byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)}
	return net.IP(b).String()
}

func cstr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}

// Map monotonic (kernel) timestamps to wall-clock epoch seconds.
func monoToEpochSec(monoNs uint64, baseEpoch time.Time, baseMonoNs uint64) float64 {
	if monoNs < baseMonoNs {
		return float64(baseEpoch.UnixNano()) / 1e9
	}
	delta := time.Duration(monoNs - baseMonoNs)
	return float64(baseEpoch.Add(delta).UnixNano()) / 1e9
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	var objPath string
	var outPath string
	var eventsPath string
	var flushSec int
	var mode string

	flag.StringVar(&objPath, "obj", "netmon.bpf.o", "compiled BPF object")
	flag.StringVar(&outPath, "out", "/tmp/ebpf_agg.jsonl", "flow aggregate JSONL output")
	flag.StringVar(&eventsPath, "events", "", "raw event JSONL output (optional)")
	flag.IntVar(&flushSec, "flush", 5, "flush interval seconds")
	flag.StringVar(&mode, "mode", "flow", "one of: flow|event|both")
	flag.Parse()

	// Avoid memlock issues
	_ = rlimit.RemoveMemlock()

	spec, err := ebpf.LoadCollectionSpec(objPath)
	must(err)

	coll, err := ebpf.NewCollection(spec)
	must(err)
	defer coll.Close()

	rbMap := coll.Maps["rb"]
	if rbMap == nil {
		panic("ringbuf map 'rb' not found")
	}

	// Attach programs
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", coll.Programs["tp_inet_sock_set_state"], nil)
	must(err)
	defer tp.Close()

	kpSend, err := link.Kprobe("tcp_sendmsg", coll.Programs["kp_tcp_sendmsg"], nil)
	must(err)
	defer kpSend.Close()

	kpClnRbuf, err := link.Kprobe("tcp_cleanup_rbuf", coll.Programs["kp_tcp_cleanup_rbuf"], nil)
	must(err)
	defer kpClnRbuf.Close()

	kpRetransmit, err := link.Kprobe("tcp_retransmit_skb", coll.Programs["kp_tcp_retransmit_skb"], nil)
	must(err)
	defer kpRetransmit.Close()

	rd, err := ringbuf.NewReader(rbMap)
	must(err)
	defer rd.Close()

	// Monotonic → epoch base
	var ts unix.Timespec
	must(unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts))
	baseMonoNs := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	baseEpoch := time.Now()

	flows := make(map[FlowKey]*FlowAgg)
	var mu sync.Mutex

	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	must(err)
	defer outFile.Close()
	outW := bufio.NewWriter(outFile)
	defer outW.Flush()

	var evW *bufio.Writer
	if eventsPath != "" {
		evFile, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		must(err)
		defer evFile.Close()
		evW = bufio.NewWriter(evFile)
		defer evW.Flush()
	}

	flush := func() {
		mu.Lock()
		defer mu.Unlock()

		nowEpoch := float64(time.Now().UnixNano()) / 1e9
		for _, a := range flows {
			a.FlushEpochS = nowEpoch
			b, _ := json.Marshal(a)
			outW.Write(b)
			outW.WriteByte('\n')
		}
		outW.Flush()
		flows = make(map[FlowKey]*FlowAgg)
	}

	ticker := time.NewTicker(time.Duration(flushSec) * time.Second)
	defer ticker.Stop()

	stopCh := make(chan os.Signal, 2)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

	fmt.Println("[*] eBPF collector running (Ctrl+C to stop)")

	go func() {
		for range ticker.C {
			if mode == "flow" || mode == "both" {
				flush()
			}
		}
	}()

	for {
		select {
		case <-stopCh:
			fmt.Println("[*] stopping, final flush...")
			if mode == "flow" || mode == "both" {
				flush()
			}
			return

		default:
			rec, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}

			want := binary.Size(Event{})
			if len(rec.RawSample) < want {
				// Skip malformed / short samples instead of panicking
				continue
			}

			var e Event
			must(binary.Read(bytes.NewBuffer(rec.RawSample[:want]), binary.LittleEndian, &e))

			// Convert kernel big-endian IPv4 to dotted string
			saddrStr := u32ToIPv4StrBE(ntohl(e.Saddr))
			daddrStr := u32ToIPv4StrBE(ntohl(e.Daddr))
			commStr := cstr(e.Comm[:])
			evEpoch := monoToEpochSec(e.TsNs, baseEpoch, baseMonoNs)

			if (mode == "event" || mode == "both") && evW != nil {
				out := RawEventOut{
					TsMonoNs:   e.TsNs,
					TsEpochS:   evEpoch,
					Pid:        e.Pid,
					Uid:        e.Uid,
					Comm:       commStr,
					Saddr:      e.Saddr,
					Daddr:      e.Daddr,
					Sport:      e.Sport,
					Dport:      e.Dport,
					Proto:      e.Proto,
					SaddrStr:   saddrStr,
					DaddrStr:   daddrStr,
					Evtype:     e.Evtype,
					StateOld:   e.StateOld,
					StateNew:   e.StateNew,
					Bytes:      e.Bytes,
					Retransmits: e.Retransmits,
				}
				b, _ := json.Marshal(out)
				evW.Write(b)
				evW.WriteByte('\n')
				evW.Flush()
			}

			if mode == "flow" || mode == "both" {
				k := FlowKey{Saddr: e.Saddr, Daddr: e.Daddr, Sport: e.Sport, Dport: e.Dport, Proto: e.Proto}

				mu.Lock()
				a := flows[k]
				if a == nil {
					a = &FlowAgg{
						FirstMonoNs: e.TsNs,
						LastMonoNs:  e.TsNs,
						FirstEpochS: evEpoch,
						LastEpochS:  evEpoch,
						Saddr:       e.Saddr,
						Daddr:       e.Daddr,
						Sport:       e.Sport,
						Dport:       e.Dport,
						Proto:       e.Proto,
						SaddrStr:    saddrStr,
						DaddrStr:    daddrStr,
						PidMode:     e.Pid,
						UidMode:     e.Uid,
						CommMode:    commStr,
					}
					flows[k] = a
				}

				a.LastMonoNs = e.TsNs
				a.LastEpochS = evEpoch
				a.Samples++

				// last-seen process (simple mode)
				a.PidMode = e.Pid
				a.UidMode = e.Uid
				a.CommMode = commStr

				switch e.Evtype {
				case 1:
					a.StateChanges++
				case 2:
					a.BytesSent += e.Bytes
				case 3:
					a.BytesRecv += e.Bytes
				case 4:
					a.Retransmits += e.Retransmits
				}

				mu.Unlock()
			}
		}
	}
}
