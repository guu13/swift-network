package main

import (
	"time"

	"github.com/guu13/swift-network/bpf/cgroup_socklb"
)

func main() {

	cgroup_socklb.InitLB4Bpf()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {

	}
}
