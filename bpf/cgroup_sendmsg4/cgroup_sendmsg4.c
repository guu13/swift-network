//go:build ignore

#include "common.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") sendmsg4_count = {
.type        = BPF_MAP_TYPE_ARRAY,
.key_size    = sizeof(u32),
.value_size  = sizeof(u64),
.max_entries = 1,
};

SEC("cgroup/sendmsg4")
int cgroup_sendmsg4_svc2pod(struct bpf_sock_addr *ctx) {
	
	 __u32 dst_ip = ctx->user_ip4;
	__u16 dst_port = (__u16)ctx->user_port ;

    __u32 _tmp_dst_ip = __bpf_ntohl(dst_ip);
    __u16 _tmp_dst_port = __bpf_ntohs(dst_port);
    __u16 tt = 9988 ;
    if(_tmp_dst_port == tt){
        bpf_printk("cgroup_sendmsg4_svc2pod, svc dst_ip:port %x:%u",dst_ip, dst_port);
        bpf_printk("cgroup_sendmsg4_svc2pod, svc dst_ip:port ntoh %x:%u",_tmp_dst_ip, _tmp_dst_port);
        bpf_printk("cgroup_sendmsg4_svc2pod, svc dst_ip:port %d.%d.%d:%d:%d", 
            ((_tmp_dst_ip>> 24) & 0xFF), ((_tmp_dst_ip>> 16) & 0xFF),((_tmp_dst_ip >> 8) & 0xFF), (_tmp_dst_ip & 0xFF), _tmp_dst_port);
    
        //33558956:49954
        ctx->user_ip4 = (__u32)33558956;
        ctx->user_port = (__u32)49954;

        _tmp_dst_ip = __bpf_ntohl(ctx->user_ip4);
        _tmp_dst_port = __bpf_ntohs(ctx->user_port);
        bpf_printk("cgroup_sendmsg4_svc2pod, pod dst_ip:port %x:%u",ctx->user_ip4, ctx->user_port);
        bpf_printk("cgroup_sendmsg4_svc2pod, pod dst_ip:port ntoh %x:%u",_tmp_dst_ip, _tmp_dst_port);
        bpf_printk("cgroup_sendmsg4_svc2pod, pod dst_ip:port %d.%d.%d.%d:%d", 
            ((_tmp_dst_ip>> 24) & 0xFF), ((_tmp_dst_ip>> 16) & 0xFF),((_tmp_dst_ip >> 8) & 0xFF), (_tmp_dst_ip & 0xFF), _tmp_dst_port);
    }

    return 1;
}