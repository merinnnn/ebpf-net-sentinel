package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	TsNs     uint64
	Pid      uint32
	Uid      uint32
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Proto    uint8
	Evtype   uint8
	StateOld uint32
	StateNew uint32
	Bytes    uint64
	Comm     [16]byte
}

func main() {
	var objPath string
	flag.StringVar(&objPath, "obj", "netmon.bpf.o", "compiled BPF object")
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

	// Graceful shutdown (Ctrl+C)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("[*] netmon running; generating events on TCP state changes (Ctrl+C to stop)")
	for {
		select {
		case <-stop:
			fmt.Println("[*] stopping...")
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

			fmt.Printf("ev=%d pid=%d uid=%d %d:%d -> %d:%d bytes=%d comm=%q\n",
				e.Evtype, e.Pid, e.Uid, e.Saddr, e.Sport, e.Daddr, e.Dport, e.Bytes, cstr(e.Comm[:]))
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
