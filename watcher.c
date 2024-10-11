//go:build ignore

// #include <linux/bpf.h>
// #include <linux/ptrace.h>
// #include <linux/sched.h>
// #include <uapi/linux/ptrace.h>
// #include <uapi/linux/bpf.h>
// #include <linux/netlink.h>
#include <vmlinux.h>
// #include "common.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#define AF_NETLINK	16

// 定义BPF map，用于用户空间和eBPF之间传递数据
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
    // ring buff: map create: invalid argument (without BTF k/v)
    // https://stackoverflow.com/questions/63415220/bpf-ring-buffer-invalid-argument-22
    // (max_entries attribute in libbpf map definition). It has to be a multiple of a memory page (which is 4096 bytes at least on most popular platforms)
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event_data {
    u32 pid;
    u32 uid;
    char comm[16];  // 进程名
};

const struct event_data *unused __attribute__((unused));


// 追踪 sendmsg 调用，过滤 netlink 消息
SEC("kprobe/netlink_sendmsg")
// https://elixir.bootlin.com/linux/v6.11.3/source/net/netlink/af_netlink.c#L1819
// The eBPF is using target specific macros, please provide -target that is not bpf, bpfel or bpfeb
// https://github.com/cilium/ebpf/discussions/772
// //go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 ...

int BPF_KPROBE(kprobe_netlink_sendmsg, struct socket *sock, struct msghdr *msg, size_t len) {
    struct event_data data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();

    // 检查是否是 netlink 消息
    if (sock->sk && sock->sk->__sk_common.skc_family == AF_NETLINK) {
        data.pid = pid;
        data.uid = uid;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        // 向用户空间发送事件
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
