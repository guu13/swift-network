package cgroup_connect4

import (
	"bufio"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf cgroup_connect4.c -- -I../headers -I/usr/include/linux/

func InitLB4Bpf() {

	log.Println("cgroup_connect4 start ")

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	//defer objs.Close()

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("detectCgroupPath ", cgroupPath)

	// Link the count_egress_packets program to the cgroup.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CgroupConnect4Svc2pod,
	})
	if err != nil {
		log.Fatal(err)
		l.Close()
	}
	//defer l.Close()
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}
