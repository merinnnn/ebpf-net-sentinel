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
	"golang.org/x/sys/unix"
)

type Event struct {
	TsMonoNs   uint64
	SockCookie uint64
	Pid        uint32
	Uid        uint32
	Saddr      uint32
	Daddr      uint32
	Sport      uint16
	Dport      uint16
	Proto      uint8
	Evtype     uint8
	Pad        uint16
	StateOld   uint32
	StateNew   uint32
	Bytes      uint64
	Comm       [16]byte
}

type FlowKey struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Proto uint8

	// Improves correlation vs plain 5-tuple
	SockCookie uint64
}

type FlowAgg struct {
	FirstMonoNs  uint64
	LastMonoNs   uint64
	FirstEpochNs int64
	LastEpochNs  int64
	BytesSent    uint64
	BytesRecv    uint64
	Retransmits  uint64
	StateChanges uint64
	Samples      uint64

	PidLast  uint32
	UidLast  uint32
	CommLast string
}

func monotonicNs() int64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano()
}

func ipToString(u uint32) string {
	ip := make(net.IP, 4)
	// u is already “network integer” (because bpf code does ntohl),
	// so BigEndian gives correct dotted IPv4.
	binary.BigEndian.PutUint32(ip, u)
	return ip.String()
}

func main() {
	var objPath string
	var outPath string
	var flushSec int
	var debugEvents bool

	flag.StringVar(&objPath, "obj", "netmon.bpf.o", "compiled BPF object")
	flag.StringVar(&outPath, "out", "ebpf_agg.jsonl", "output JSONL (flow-level aggregates)")
	flag.IntVar(&flushSec, "flush", 5, "flush interval seconds")
	flag.BoolVar(&debugEvents, "debug_events", false, "print decoded events to stdout")
	flag.Parse()

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
	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	attach := func(l link.Link, err error) {
		must(err)
		links = append(links, l)
	}

	attach(link.Tracepoint("sock", "inet_sock_set_state", coll.Programs["tp_inet_sock_set_state"], nil))
	attach(link.Kprobe("tcp_sendmsg", coll.Programs["kp_tcp_sendmsg"], nil))
	attach(link.Kprobe("tcp_cleanup_rbuf", coll.Programs["kp_tcp_cleanup_rbuf"], nil))
	attach(link.Kprobe("tcp_retransmit_skb", coll.Programs["kp_tcp_retransmit_skb"], nil))

	rd, err := ringbuf.NewReader(rbMap)
	must(err)
	defer rd.Close()

	// Time alignment: map monotonic -> epoch
	startWallNs := time.Now().UnixNano()
	startMonoNs := monotonicNs()

	// Output file
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	must(err)
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	defer w.Flush()

	// Aggregation store
	var mu sync.Mutex
	flows := map[FlowKey]*FlowAgg{}

	monoToEpoch := func(mono uint64) int64 {
		// epoch_ns = startWall + (mono - startMono)
		return startWallNs + int64(mono) - startMonoNs
	}

	flush := func() {
		mu.Lock()
		defer mu.Unlock()

		flushWall := time.Now().UnixNano()
		for k, a := range flows {
			row := map[string]any{
				"flush_wall_ts_ns": flushWall,
				"saddr":       		ipToString(k.Saddr),
				"daddr":       		ipToString(k.Daddr),
				"saddr_u32":   		k.Saddr,
				"daddr_u32":   		k.Daddr,
				"sport":       		k.Sport,
				"dport":      		k.Dport,
				"proto":      		k.Proto,
				"sock_cookie":   	k.SockCookie,
				"first_mono_ns":  	a.FirstMonoNs,
				"last_mono_ns":   	a.LastMonoNs,
				"first_epoch_ns": 	a.FirstEpochNs,
				"last_epoch_ns": 	a.LastEpochNs,
				"bytes_sent":   	a.BytesSent,
				"bytes_recv":   	a.BytesRecv,
				"retransmits":  	a.Retransmits,
				"state_changes": 	a.StateChanges,
				"samples":       	a.Samples,
				"pid_last":  		a.PidLast,
				"uid_last":  		a.UidLast,
				"comm_last": 		a.CommLast,
			}

			b, _ := json.Marshal(row)
			_, _ = w.Write(append(b, '\n'))
			delete(flows, k)
		}
		_ = w.Flush()
	}

	ticker := time.NewTicker(time.Duration(flushSec) * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for range ticker.C {
			flush()
		}
	}()

	fmt.Println("[*] eBPF collector running (Ctrl+C to stop)")
	for {
		select {
		case <-stop:
			fmt.Println("[*] stopping, final flush...")
			flush()
			return

		default:
			rec, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}

			var e Event
			must(binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &e))

			if debugEvents {
				fmt.Printf("ev=%d pid=%d uid=%d %s:%d -> %s:%d bytes=%d cookie=%d comm=%q\n",
					e.Evtype, e.Pid, e.Uid,
					ipToString(e.Saddr), e.Sport, ipToString(e.Daddr), e.Dport,
					e.Bytes, e.SockCookie, cstr(e.Comm[:]),
				)
			}

			key := FlowKey{
				Saddr:       e.Saddr,
				Daddr:       e.Daddr,
				Sport:       e.Sport,
				Dport:       e.Dport,
				Proto:       e.Proto,
				SockCookie:  e.SockCookie,
			}

			epoch := monoToEpoch(e.TsMonoNs)

			mu.Lock()
			a := flows[key]
			if a == nil {
				a = &FlowAgg{
					FirstMonoNs:  e.TsMonoNs,
					LastMonoNs:   e.TsMonoNs,
					FirstEpochNs: epoch,
					LastEpochNs:  epoch,
					PidLast:      e.Pid,
					UidLast:      e.Uid,
					CommLast:     cstr(e.Comm[:]),
				}
				flows[key] = a
			}

			if e.TsMonoNs < a.FirstMonoNs {
				a.FirstMonoNs = e.TsMonoNs
				a.FirstEpochNs = epoch
			}
			if e.TsMonoNs > a.LastMonoNs {
				a.LastMonoNs = e.TsMonoNs
				a.LastEpochNs = epoch
			}

			a.Samples++
			a.PidLast = e.Pid
			a.UidLast = e.Uid
			a.CommLast = cstr(e.Comm[:])

			switch e.Evtype {
			case 2:
				a.BytesSent += e.Bytes
			case 3:
				a.BytesRecv += e.Bytes
			case 4:
				a.Retransmits++
			case 1:
				a.StateChanges++
			}
			mu.Unlock()
		}
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func cstr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}
