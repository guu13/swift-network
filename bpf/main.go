package main

import (
	"log"
	"time"

	"github.com/guu13/swift-network/bpf/cgroup_connect4"
	"github.com/guu13/swift-network/bpf/cgroup_getpeername4"
	"github.com/guu13/swift-network/bpf/cgroup_sendmsg4"
)

func main() {

	cgroup_connect4.InitLB4Bpf()

	cgroup_getpeername4.InitLB4Bpf()

	cgroup_sendmsg4.InitLB4Bpf()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("ticker...")
	}
}
