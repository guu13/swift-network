// This program demonstrates attaching an eBPF program to a control group.
// The eBPF program will be attached as an egress filter,
// receiving an `__sk_buff` pointer for each outgoing packet.
// It prints the count of total packets every second.
package cgroup_skb

import "fmt"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf cgroup_skb.c -- -I../headers

func init() {
	fmt.Println("init bpf cgroup_skb")
}
