//go:build ignore

#include "common.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";


struct lb4_key {
	__be32 address;		/* Service virtual IPv4 address */
	__be16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 backend_slot;	/* Backend iterator, 0 indicates the svc frontend */
	__u8 proto;		/* L4 protocol, currently not used (set to 0) */
	__u8 scope;		/* LB_LOOKUP_SCOPE_* for externalTrafficPolicy=Local */
	__u8 pad[2];
} lb4_key ;

struct lb4_service {
	union {
		__u32 backend_id;	/* Backend ID in lb4_backends */
		__u32 affinity_timeout;	/* In seconds, only for svc frontend */
		__u32 l7_lb_proxy_port;	/* In host byte order, only when flags2 && SVC_FLAG_L7LOADBALANCER */
	};
	/* For the service frontend, count denotes number of service backend
	 * slots (otherwise zero).
	 */
	__u16 count;
	__u16 rev_nat_index;	/* Reverse NAT ID in lb4_reverse_nat */
	__u8 flags;
	__u8 flags2;
	__u8  pad[2];
} lb4_service;

struct lb4_backend {
	__be32 address;		/* Service endpoint IPv4 address */
	__be16 port;		/* L4 port filter */
	__u8 proto;		/* L4 protocol, currently not used (set to 0) */
	__u8 flags;
	__u8 cluster_id;	/* With this field, we can distinguish two
				 * backends that have the same IP address,
				 * but belong to the different cluster.
				 */
	__u8 pad[3];
} lb4_backend;

struct bpf_map_def SEC("maps") sn_lb4_svc_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(lb4_key),
    .value_size  = sizeof(lb4_service),
    .max_entries = 65535,
    .map_flags = 1,
};

struct bpf_map_def SEC("maps") sn_lb4_pod_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(lb4_backend),
    .max_entries = 65535,
    .map_flags = 1,
};

/* Hack due to missing narrow ctx access. */
static __always_inline  __be16
ctx_dst_port(const struct bpf_sock_addr *ctx)
{
	volatile __u32 dport = ctx->user_port;

	return (__be16)dport;
}

SEC("cgroup/connect4")
int cgroup_connect4_svc2pod(struct bpf_sock_addr *ctx) {
    struct lb4_backend *backend;
	struct lb4_service *svc;
    __u32 dst_ip = ctx->user_ip4;
	__u16 dst_port = ctx_dst_port(ctx) ;
	struct lb4_key key = {
		.address	= dst_ip, 
		.dport		= dst_port,
	}, orig_key = key;

    __u32 _tmp_dst_ip = __bpf_ntohl(dst_ip);
    __u16 _tmp_dst_port = __bpf_ntohs(dst_port);
    __u16 tt = 9988 ;
    if(_tmp_dst_port == tt){
        bpf_printk("cgroup_connect4_svc2pod, svc dst_ip:port %x:%u, protocol:%u",dst_ip, dst_port, ctx->protocol);
        bpf_printk("cgroup_connect4_svc2pod, svc dst_ip:port ntoh %x:%u",_tmp_dst_ip, _tmp_dst_port);
        bpf_printk("cgroup_connect4_svc2pod, svc dst_ip:port %d.%d.%d:%d:%d", 
            ((_tmp_dst_ip>> 24) & 0xFF), ((_tmp_dst_ip>> 16) & 0xFF),((_tmp_dst_ip >> 8) & 0xFF), (_tmp_dst_ip & 0xFF), _tmp_dst_port);
    
        //33558956:49954
        ctx->user_ip4 = (__u32)33558956;
        ctx->user_port = (__u32)49954;

        _tmp_dst_ip = __bpf_ntohl(ctx->user_ip4);
        _tmp_dst_port = __bpf_ntohs(ctx->user_port);
        bpf_printk("cgroup_connect4_svc2pod, pod dst_ip:port %x:%u",ctx->user_ip4, ctx->user_port);
        bpf_printk("cgroup_connect4_svc2pod, pod dst_ip:port ntoh %x:%u",_tmp_dst_ip, _tmp_dst_port);
        bpf_printk("cgroup_connect4_svc2pod, pod dst_ip:port %d.%d.%d.%d:%d", 
            ((_tmp_dst_ip>> 24) & 0xFF), ((_tmp_dst_ip>> 16) & 0xFF),((_tmp_dst_ip >> 8) & 0xFF), (_tmp_dst_ip & 0xFF), _tmp_dst_port);
        
        return 1;
    }
    
    svc = bpf_map_lookup_elem(&sn_lb4_svc_map, &key);
    if(svc)
        return 1;

    




    return 1;
}