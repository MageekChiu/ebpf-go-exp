package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -target amd64 -type event_data watcher watcher.c -- -I headers


import (
    "os"
    "errors"
    "os/signal"
    "syscall"
	"log"
    "bytes"
	"encoding/binary"
    "golang.org/x/sys/unix"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"

)

func main() {
    // Name of the kernel function to trace.
	// fn := "sys_setsockopt"
    // Subscribe to signals for terminating the program.
    stopper := make(chan os.Signal, 1)
    signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

    // 加载编译后的 eBPF 对象
    objects := watcherObjects{}
	if err := loadWatcherObjects(&objects, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objects.Close()

    // // kp, err := link.Kprobe(fn, objects.KprobeSysSetsockopt, nil)
    // kp, err := link.Kprobe(fn, objects.BpfProg, nil)
	// if err != nil {
	// 	log.Fatalf("opening kprobe: %s", err)
	// }
	// defer kp.Close()

     // Attach the eBPF program to the tracepoint for sys_enter_setsockopt
     tp, err := link.Tracepoint("syscalls", "sys_enter_setsockopt", objects.TracepointSetsockopt, nil)
     if err != nil {
         log.Fatalf("failed to attach tracepoint: %v", err)
     }
     defer tp.Close()


    // Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	// bpfEvent is generated by bpf2go.
	var event watcherEventData
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

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("pid: %d\tcomm: %s\n", event.Pid, unix.ByteSliceToString(event.Comm[:]))
	}
 

    
}
