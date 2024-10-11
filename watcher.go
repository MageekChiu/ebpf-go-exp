package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -target amd64 -type event_data watcher watcher.c -- -I headers


import (
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/perf"
)

func main1() {
    // 加载编译后的 eBPF 对象
    objects := struct {
        Events *ebpf.Map
    }{}

    if err := loadWatcherObjects(&objects, nil); err != nil {
        fmt.Fprintf(os.Stderr, "loading objects: %v\n", err)
        os.Exit(1)
    }
    defer objects.Events.Close()

    // 监听 Perf 事件
    rd, err := perf.NewReader(objects.Events, os.Getpagesize())
    if err != nil {
        fmt.Fprintf(os.Stderr, "opening perf reader: %v\n", err)
        os.Exit(1)
    }
    defer rd.Close()

    // 捕获终止信号
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigs
        fmt.Println("Received signal, exiting...")
        rd.Close()
        os.Exit(0)
    }()

    fmt.Println("Listening for netlink events...")

    for {
        record, err := rd.Read()
        if err != nil {
            fmt.Fprintf(os.Stderr, "reading from perf event reader: %v\n", err)
            continue
        }

        if record.LostSamples > 0 {
            fmt.Printf("Lost %d samples\n", record.LostSamples)
            continue
        }

        var event watcherEventData

        fmt.Printf("Process %s (PID: %d, UID: %d) sent a netlink message\n", event.Comm, event.Pid, event.Uid)
    }
}
