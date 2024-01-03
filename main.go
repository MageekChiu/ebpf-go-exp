package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event counter counter.c -- -I headers
// -type is for: struct event

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func main() {
	// // Remove resource limits for kernels <5.11.
	// if err := rlimit.RemoveMemlock(); err != nil {
	// 	log.Fatal("Removing memlock:", err)
	// }

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := "enp0s1" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	rd, err := ringbuf.NewReader(objs.Events1)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	// counterEvent is generated by bpf2go.
	var event counterEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		log.Printf("tuple num: %d", event.Count)

		var (
			key counterTuple
			val uint32
		)
		iter := objs.PktCountMap.Iterate()
		for iter.Next(&key, &val) {
			sourceIP := key.Addr
			sourcePort := key.Port
			packetCount := val
			log.Printf("%d:%d => %d\n", sourceIP, sourcePort, packetCount)
		}
	}
}