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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_NETLINK	16

// 定义BPF map，用于用户空间和eBPF之间传递数据
// struct {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
//     // ring buff: map create: invalid argument (without BTF k/v)
//     // https://stackoverflow.com/questions/63415220/bpf-ring-buffer-invalid-argument-22
//     // (max_entries attribute in libbpf map definition). It has to be a multiple of a memory page (which is 4096 bytes at least on most popular platforms)
// 	__uint(max_entries, 1 << 24);
// } events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct event_data {
    u32 pid;
    u32 uid;
	u8 comm[TASK_COMM_LEN];
};

const struct event_data *unused __attribute__((unused));

/*

// 追踪 sendmsg 调用，过滤 netlink 消息
SEC("kprobe/netlink_sendmsg")
// https://elixir.bootlin.com/linux/v6.11.3/source/net/netlink/af_netlink.c#L1819
// The eBPF is using target specific macros, please provide -target that is not bpf, bpfel or bpfeb
// https://github.com/cilium/ebpf/discussions/772
// //go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 ...
// NetlinkSendmsg: unknown program netlink_sendmsg
int BPF_KPROBE(netlink_sendmsg, struct socket *sock, struct msghdr *msg, size_t len) {
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
*/

#define SOL_IP		0
#define IPT_SO_SET_REPLACE 64 // 替换 iptables 规则的选项

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_setsockopt/enable
// 捕获 tracepoint 的 setsockopt 系统调用入口
SEC("tracepoint/syscalls/sys_enter_setsockopt")
int tracepoint_setsockopt(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];       // 文件描述符
    int level = ctx->args[1];    // 协议层级
    int optname = ctx->args[2];  // 选项名
    int optlen = ctx->args[4];   // 选项长度

// // BPF_KPROBE supports up to five parameters, so we can't get the rest
// SEC("kprobe/__sys_setsockopt")
// int BPF_KPROBE(kprobe_sys_setsockopt, 
//     int fd, int level, int optname, char __user ){//*user_optval){//,int optlen){

// // 捕获 setsockopt() 系统调用
// SEC("kprobe/sys_setsockopt")
// int bpf_prog(struct pt_regs *ctx) {
//     int fd = PT_REGS_PARM1(ctx);       // 文件描述符
//     int level = PT_REGS_PARM2(ctx);    // 套接字协议层
//     int optname = PT_REGS_PARM3(ctx);  // 选项名
//     const void *optval = (void *)PT_REGS_PARM4(ctx); // 选项值
//     int optlen = PT_REGS_PARM5(ctx);   // 选项长度

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();

    bpf_printk("setsockopt called: pid=%d, sockfd=%d, level=%d, optname=%d, optlen=%d"
        , pid, fd,level, optname, optlen);
    // 只对 level == SOL_NETFILTER 的 setsockopt 进行监控
    if (level == SOL_IP && optname == IPT_SO_SET_REPLACE) {
        // 记录一些信息，比如进程 ID
        struct event_data *data;

        data = bpf_ringbuf_reserve(&events, sizeof(struct event_data), 0);
        if (!data) {
            return 0;
        }
       
        data->pid = pid;
        data->uid = uid;
	    bpf_get_current_comm(&data->comm, TASK_COMM_LEN);
        bpf_printk("iptables setsockopt called: pid=%d, sockfd=%d, optname=%d\n", pid, fd, optname);
	    bpf_ringbuf_submit(data, 0);
    }

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
// char LICENSE[] SEC("license") = "Dual BSD/GPL";

