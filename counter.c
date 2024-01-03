
//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1: 4;
	__u16 doff: 4;
	__u16 fin: 1;
	__u16 syn: 1;
	__u16 rst: 1;
	__u16 psh: 1;
	__u16 ack: 1;
	__u16 urg: 1;
	__u16 ece: 1;
	__u16 cwr: 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

struct tuple {
    __u32 addr;
	__u16 port;
};

#define MAX_MAP_ENTRIES 1024
#define ETH_P_IP	0x0800	
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, struct tuple); 
	__type(value, __u32);
} pkt_count_map SEC(".maps"); 

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_MAP_ENTRIES);
} events1 SEC(".maps");

// Emit struct event's type info into the ELF's BTF so bpf2go
// can generate a Go type from it.
struct event {
	__u32 count;
};
const struct event *unused __attribute__((unused));
// const struct event *unused = {0};

__u32 *tuple_num = 0;;

static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr, __u16 *src_port) {
	void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int pkt_sz = data_end - data;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(ETH_P_IP)){
        return 0;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return 0;
    *ip_src_addr = (__u32)(iph->saddr);

    __u16 sport,dport;
    struct tcphdr *tcph;
    struct udphdr *udph;
    // u8,so no big or little edian
    if (iph->protocol == IPPROTO_TCP){
        tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
            return 0;
        sport = tcph->source;
        dport = tcph->dest;
    }else if(iph->protocol == IPPROTO_UDP){
        udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return 0;
        sport = udph->source;
        dport = udph->dest;
    }else{
        bpf_printk("unknown protocol:%u, pass",iph->protocol);
        return 0;
    }
    *src_port = sport;

    return 1;
}

SEC("xdp") 
int count_packets(struct xdp_md *ctx) {
    __u32 ip;
    __u16 sport;
	if (!parse_ip_src_addr(ctx, &ip, &sport)){
		goto done;
	}
    struct tuple key = {ip,sport};

	__u32 *pkt_count = bpf_map_lookup_elem(&pkt_count_map, &key);
	if (!pkt_count) {
		__u32 init_pkt_count = 1;
		bpf_map_update_elem(&pkt_count_map, &ip, &init_pkt_count, BPF_ANY);

		__sync_fetch_and_add(tuple_num, 1);
        if(*tuple_num %5 == 0){
            struct event *e;
            e = bpf_ringbuf_reserve(&events1, sizeof(struct event), 0);
            if (e){
                e->count = *tuple_num;
                bpf_ringbuf_submit(e, 0);
            }
           
        }
	} else {
		__sync_fetch_and_add(pkt_count, 1);
	}

done:
	return XDP_PASS; 
}

char __license[] SEC("license") = "Dual MIT/GPL";