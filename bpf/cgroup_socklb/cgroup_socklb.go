package cgroup_socklb

import (
	"bufio"
	"errors"
	"log"
	"net"
	"os"
	"path"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/guu13/swift-network/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf cgroup_socklb.c -- -I../headers -I/usr/include/linux/

type pad2uint8 [2]uint8

// Service4Key must match 'struct lb4_key' in "bpf/lib/common.h".
type Service4Key struct {
	Address     types.IPv4 `align:"address"`
	Port        uint16     `align:"dport"`
	BackendSlot uint16     `align:"backend_slot"`
	Proto       uint8      `align:"proto"`
	Scope       uint8      `align:"scope"`
	Pad         pad2uint8  `align:"pad"`
}

// Service4Value must match 'struct lb4_service_v2' in "bpf/lib/common.h".
type Service4Value struct {
	BackendID uint32    `align:"$union0"`
	Count     uint16    `align:"count"`
	RevNat    uint16    `align:"rev_nat_index"`
	Flags     uint8     `align:"flags"`
	Flags2    uint8     `align:"flags2"`
	Pad       pad2uint8 `align:"pad"`
}

func InitLB4Bpf() {

	svcValue := Service4Value{}

	log.Println("cgroup_socklb start ")

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	pinPath := path.Join("/sys/fs/bpf/", "sn_map")
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	//defer objs.Close()

	svcip := net.IPv4(0x10, 0x10, 0x10, 0x10)

	svckey := Service4Key{
		Port:        uint16(16),
		Proto:       uint8(8),
		Scope:       uint8(8),
		BackendSlot: uint16(16)}
	copy(svckey.Address[:], svcip.To4())

	// key: 10 10 10 10 10 00 10 00  08 08 00 00  value: 0d 00 00 00 0d 00 0d 00  03 03 00 00
	if err := objs.SnLb4SvcMap.Lookup(svckey, svcValue); err != nil {
		log.Println(err)
	}

	svcValue = Service4Value{BackendID: uint32(13), Count: uint16(13), RevNat: uint16(13), Flags: uint8(3), Flags2: uint8(3)}
	if err := objs.SnLb4SvcMap.Update(svckey, svcValue, ebpf.UpdateAny); err != nil {
		log.Println(err)
	}

	if err := objs.SnLb4SvcMap.Lookup(svckey, svcValue); err != nil {
		log.Println(err)
	}

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatal(err)
	}
	//cgroupPath = cgroupPath + "/swift"
	log.Println("detectCgroupPath ", cgroupPath)

	objs.SnLb4SvcMap.Pin("/sys/fs/bpf/sn_map/sn_lb4svc_map")
	objs.CgroupConnect4Svc2pod.Pin("/sys/fs/bpf/sn_map/sn_connect_prog")

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

	// Link the count_egress_packets program to the cgroup.
	linkPeer, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCgroupInet4GetPeername,
		Program: objs.CgroupGetpeername4Pod2svc,
	})

	if err != nil {
		log.Fatal(err)
		linkPeer.Close()
	}

	// Link the count_egress_packets program to the cgroup.
	linkSendMsg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupUDP4Sendmsg,
		Program: objs.CgroupSendmsg4Svc2pod,
	})
	if err != nil {
		log.Fatal(err)
		linkSendMsg.Close()
	}
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
