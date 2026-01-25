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
	Oldstate uint32
	Newstate uint32
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
		fmt.Printf("pid=%d %d->%d ts=%d\n", e.Pid, e.Oldstate, e.Newstate, e.TsNs)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
