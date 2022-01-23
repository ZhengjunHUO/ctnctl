#include <linux/bpf.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <stdbool.h>
#include "bpf_helpers.h"

/* store network packet's info */
typedef struct {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  bitmap;
} pkt;

/* used as key in L4 blacklist */
typedef struct {
    __u32 addr;
    __u16 port;
    __u16 reserved;
} skt;

/* store L3 blacklist rules for ingress */
struct bpf_map_def SEC("maps") ingress_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(_Bool),
    .max_entries = 1000,
};

/* store L3 blacklist rules for egress */
struct bpf_map_def SEC("maps") egress_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(_Bool),
    .max_entries = 1000,
};

/* store L4 blacklist rules for ingress */
struct bpf_map_def SEC("maps") ingress_l4_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(skt),
    .value_size = sizeof(_Bool),
    .max_entries = 1000,
};

/* store L4 blacklist rules for egress */
struct bpf_map_def SEC("maps") egress_l4_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(skt),
    .value_size = sizeof(_Bool),
    .max_entries = 1000,
};

/* store network flow logs for container */
struct bpf_map_def SEC("maps") data_flow = {
    .type = BPF_MAP_TYPE_QUEUE,
    .key_size = 0,
    .value_size = sizeof(pkt),
    .max_entries = 1000,
};

/* apply saved rules to ingress/egress packets, drop the packet if match */
static inline int filter_packet(struct __sk_buff *skb, bool isIngress) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct iphdr *iphd = data;
    __u32 iphdr_len = sizeof(struct iphdr);
    // avoid verifier's complain
    if (data + iphdr_len > data_end)
        return 1;

    skt s;
    // initialize padding to avoid verifier's complain
    __builtin_memset(&s, 0, sizeof(skt));

    pkt p;
    // initialize padding to avoid verifier's complain
    __builtin_memset(&p, 0, sizeof(pkt));

    p.saddr = iphd->saddr;
    p.daddr = iphd->daddr;
    p.proto = iphd->protocol;

    if (iphd->protocol == IPPROTO_TCP) {
        struct tcphdr *tcphd = data + iphdr_len;
        __u32 tcphdr_len = sizeof(struct tcphdr);
        // avoid verifier's complain
        if ((void *)tcphd + tcphdr_len > data_end)
            return 1;

        p.sport = tcphd->source;
        p.dport = tcphd->dest;
    }

    if (iphd->protocol == IPPROTO_UDP) {
        struct udphdr *udphd = data + iphdr_len;
        __u32 udphdr_len = sizeof(struct udphdr);
        // avoid verifier's complain
        if ((void *)udphd + udphdr_len > data_end)
            return 1;

        p.sport = udphd->source;
        p.dport = udphd->dest;
    }

    bool isBannedL3;
    bool isBannedL4;
    if (isIngress) {
        bpf_printk("Ingress from %lu",iphd->saddr);
	s.addr = p.saddr;
	// we don't care source port
	s.port = p.dport;
	isBannedL3 = bpf_map_lookup_elem(&ingress_blacklist, &iphd->saddr);
	isBannedL4 = bpf_map_lookup_elem(&ingress_l4_blacklist, &s);
    }else{
        bpf_printk("Egress to %lu",iphd->daddr);
	s.addr = p.daddr;
	s.port = p.dport;
	isBannedL3 = bpf_map_lookup_elem(&egress_blacklist, &iphd->daddr);
	isBannedL4 = bpf_map_lookup_elem(&egress_l4_blacklist, &s);
    }

    p.bitmap = (isBannedL3 << 1) | (isBannedL4 << 2) | isIngress;

    // save logs
    bpf_map_push_elem(&data_flow, &p, BPF_ANY);

    // return 0 => drop
    if (p.bitmap > 1) {
        return 0;
    }

    return 1;
}

SEC("cgroup_skb/ingress")
int ingress_filter(struct __sk_buff *skb) {
    return filter_packet(skb, true);
}

SEC("cgroup_skb/egress")
int egress_filter(struct __sk_buff *skb) {
    return filter_packet(skb, false);
}

char __license[] SEC("license") = "Dual MIT/GPL";
