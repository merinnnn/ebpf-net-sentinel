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
	"path/filepath"
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

	Comm   [16]byte
	PadEnd uint32 // explicit tail pad (matches C struct)
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

const (
	ethPAll        uint16 = 0x0003 // ETH_P_ALL
	packetOutgoing uint32 = 4      // PACKET_OUTGOING (matches BPF constant)
)

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}

// Open AF_PACKET socket bound to iface, for attaching socket filter (SO_ATTACH_BPF).
func openAndBindAFPacket(iface string) (int, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return -1, err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return -1, err
	}

	sa := &unix.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  ifc.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	
	return fd, nil
}

func attachSocketFilter(fd int, prog *ebpf.Program) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD())
}

func detachSocketFilter(fd int) error {
	// SO_DETACH_BPF ignores optval; use 0.
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0)
}

func readJSONFile(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func main() {
	var objPath string
	var outPath string
	var eventsPath string
	var flushSec int
	var mode string
	var pktIface string
	var disableKprobes bool
	var metaPath string
	var tcpreplayMetaPath string

	flag.StringVar(&objPath, "obj", "netmon.bpf.o", "compiled BPF object")
	flag.StringVar(&outPath, "out", "/tmp/ebpf_agg.jsonl", "flow aggregate JSONL output")
	flag.StringVar(&eventsPath, "events", "", "raw event JSONL output (optional)")
	flag.IntVar(&flushSec, "flush", 5, "flush interval seconds")
	flag.StringVar(&mode, "mode", "flow", "one of: flow|event|both")
	flag.StringVar(&pktIface, "pkt_iface", "", "if set, attach a socket filter to capture packets on this interface (works with tcpreplay)")
	flag.BoolVar(&disableKprobes, "disable_kprobes", false, "skip kprobes/tracepoints (useful when using pkt_iface only)")
	flag.StringVar(&metaPath, "meta", "", "optional JSON file to write a run summary (counts + config)")
	flag.StringVar(&tcpreplayMetaPath, "tcpreplay_meta", "", "optional JSON file produced by run_capture.sh (embedded into run summary if present)")
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

	// Attach kprobes/tracepoints
	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	// Optional packet capture socket filter for tcpreplay visibility.
	pktFd := -1
	if pktIface != "" {
		prog := coll.Programs["sock_packet"]
		if prog == nil {
			panic("program 'sock_packet' not found in collection")
		}

		fd, err := openAndBindAFPacket(pktIface)
		must(err)
		pktFd = fd

		must(attachSocketFilter(pktFd, prog))
		defer func() {
			_ = detachSocketFilter(pktFd)
			_ = unix.Close(pktFd)
		}()
	}

	if !disableKprobes {
		tp, err := link.Tracepoint("sock", "inet_sock_set_state", coll.Programs["tp_inet_sock_set_state"], nil)
		must(err)
		links = append(links, tp)

		kpSend, err := link.Kprobe("tcp_sendmsg", coll.Programs["kp_tcp_sendmsg"], nil)
		must(err)
		links = append(links, kpSend)

		kpClnRbuf, err := link.Kprobe("tcp_cleanup_rbuf", coll.Programs["kp_tcp_cleanup_rbuf"], nil)
		must(err)
		links = append(links, kpClnRbuf)

		kpRetransmit, err := link.Kprobe("tcp_retransmit_skb", coll.Programs["kp_tcp_retransmit_skb"], nil)
		must(err)
		links = append(links, kpRetransmit)
	}

	rd, err := ringbuf.NewReader(rbMap)
	must(err)
	defer rd.Close()

	// Close rd to unblock rd.Read() ---
	stopCh := make(chan os.Signal, 2)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopCh)

	stopping := make(chan struct{})
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			close(stopping)
			_ = rd.Close() // unblocks rd.Read()
		})
	}

	go func() {
		<-stopCh
		stop()
	}()

	// Monotonic → epoch base
	var ts unix.Timespec
	must(unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts))
	baseMonoNs := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	baseEpoch := time.Now()

	startTime := time.Now()
	var eventsRead uint64
	var flowsFlushed uint64

	// Periodic progress logs
	progress := time.NewTicker(2 * time.Second)
	defer progress.Stop()

	go func() {
		for range progress.C {
			mu.Lock()
			nflows := len(flows)
			mu.Unlock()

			fmt.Printf("[*] progress: events=%d active_flows=%d flushed=%d out=%s\n",
				eventsRead, nflows, flowsFlushed, outPath)
		}
	}()

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
			_, _ = outW.Write(b)
			_ = outW.WriteByte('\n')
		}
		_ = outW.Flush()
		flowsFlushed += uint64(len(flows))
		flows = make(map[FlowKey]*FlowAgg)
	}

	// periodic flush, stops when stopping closes
	ticker := time.NewTicker(time.Duration(flushSec) * time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-stopping:
				return
			case <-ticker.C:
				if mode == "flow" || mode == "both" {
					flush()
				}
			}
		}
	}()

	fmt.Println("[*] eBPF collector running (Ctrl+C to stop)")

	for {
		rec, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				break
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
		eventsRead++

		// Normalize addresses: BPF emits __be32; on little-endian hosts we must ntohl.
		saddrU32 := ntohl(e.Saddr)
		daddrU32 := ntohl(e.Daddr)
		saddrStr := u32ToIPv4StrBE(saddrU32)
		daddrStr := u32ToIPv4StrBE(daddrU32)
		commStr := cstr(e.Comm[:])
		evEpoch := monoToEpochSec(e.TsNs, baseEpoch, baseMonoNs)

		if (mode == "event" || mode == "both") && evW != nil {
			out := RawEventOut{
				TsMonoNs:    e.TsNs,
				TsEpochS:    evEpoch,
				Pid:         e.Pid,
				Uid:         e.Uid,
				Comm:        commStr,
				Saddr:       saddrU32,
				Daddr:       daddrU32,
				Sport:       e.Sport,
				Dport:       e.Dport,
				Proto:       e.Proto,
				SaddrStr:    saddrStr,
				DaddrStr:    daddrStr,
				Evtype:      e.Evtype,
				StateOld:    e.StateOld,
				StateNew:    e.StateNew,
				Bytes:       e.Bytes,
				Retransmits: e.Retransmits,
			}
			b, _ := json.Marshal(out)
			_, _ = evW.Write(b)
			_ = evW.WriteByte('\n')
		}

		if mode == "flow" || mode == "both" {
			k := FlowKey{Saddr: saddrU32, Daddr: daddrU32, Sport: e.Sport, Dport: e.Dport, Proto: e.Proto}

			mu.Lock()
			a := flows[k]
			if a == nil {
				a = &FlowAgg{
					FirstMonoNs: e.TsNs,
					LastMonoNs:  e.TsNs,
					FirstEpochS: evEpoch,
					LastEpochS:  evEpoch,
					Saddr:       saddrU32,
					Daddr:       daddrU32,
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
			case 5:
				if e.StateOld == packetOutgoing {
					a.BytesSent += e.Bytes
				} else {
					a.BytesRecv += e.Bytes
				}
			}
			mu.Unlock()
		}
	}

	// Final flush + meta write (always runs after loop exits)
	fmt.Println("[*] stopping, final flush...")

	if mode == "flow" || mode == "both" {
		flush()
	}
	_ = outW.Flush()
	if evW != nil {
		_ = evW.Flush()
	}

	finalMeta := metaPath
	if finalMeta == "" {
		finalMeta = outPath + ".meta.json"
	}

	summary := map[string]any{
		"start_rfc3339":   startTime.UTC().Format(time.RFC3339),
		"end_rfc3339":     time.Now().UTC().Format(time.RFC3339),
		"duration_s":      time.Since(startTime).Seconds(),
		"obj":             objPath,
		"out":             outPath,
		"events":          eventsPath,
		"flush_s":         flushSec,
		"mode":            mode,
		"pkt_iface":       pktIface,
		"disable_kprobes": disableKprobes,
		"events_read":     eventsRead,
		"flows_flushed":   flowsFlushed,
	}

	if tcpreplayMetaPath != "" {
		if m, err := readJSONFile(tcpreplayMetaPath); err == nil {
			summary["tcpreplay"] = m
		} else {
			summary["tcpreplay_error"] = err.Error()
		}
	}

	if err := os.MkdirAll(filepath.Dir(finalMeta), 0o755); err == nil {
		if b, err := json.MarshalIndent(summary, "", "  "); err == nil {
			_ = os.WriteFile(finalMeta, b, 0o644)
			fmt.Println("[*] wrote run meta:", finalMeta)
		}
	}

	// pktFd is handled by defer, but keep a safety close if you ever refactor defers.
	_ = pktFd
}
