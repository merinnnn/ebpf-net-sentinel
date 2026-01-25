package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
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

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", coll.Programs["tp_inet_sock_set_state"], nil)
	must(err)
	defer tp.Close()

	kpSend, err := link.Kprobe("tcp_sendmsg", coll.Programs["kp_tcp_sendmsg"], nil)
	must(err)
	defer kpSend.Close()

	kpClnRbuf, err := link.Kprobe("tcp_cleanup_rbuf", coll.Programs["kp_tcp_cleanup_rbuf"], nil)
	must(err)
	defer kpClnRbuf.Close()

	rd, err := ringbuf.NewReader(rbMap)
	must(err)
	defer rd.Close()

	fmt.Println("[*] netmon running; generating events on TCP state changes")
	for {
		rec, err := rd.Read()
		if err != nil {
			continue
		}
		var e Event
		must(binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &e))
		fmt.Printf("ev=%d pid=%d uid=%d %d:%d -> %d:%d bytes=%d comm=%q\n", 
			e.Evtype, e.Pid, e.Uid, e.Saddr, e.Sport, e.Daddr, e.Dport, e.Bytes, cstr(e.Comm[:]))

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

