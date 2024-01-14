package lbmap

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/guu13/swift-network/pkg/bpf"
	"github.com/guu13/swift-network/pkg/byteorder"
	"github.com/guu13/swift-network/pkg/types"
	"github.com/guu13/swift-network/pkg/u8proto"
	"net"
)

type pad2uint8 [2]uint8

const (
	// Service4MapV2Name is the name of the IPv4 LB Services v2 BPF map.
	Service4MapV2Name = "swift_lb4_services_v2"
)

var (
	// Service4MapV2 is the IPv4 LB Services v2 BPF map.
	Service4MapV2 *bpf.Map
)

// Service4Key must match 'struct lb4_key' in "bpf/lib/common.h".
type Service4Key struct {
	Address     types.IPv4 `align:"address"`
	Port        uint16     `align:"dport"`
	BackendSlot uint16     `align:"backend_slot"`
	Proto       uint8      `align:"proto"`
	Scope       uint8      `align:"scope"`
	Pad         pad2uint8  `align:"pad"`
}

func NewService4Key(ip net.IP, port uint16, proto u8proto.U8proto, scope uint8, slot uint16) *Service4Key {
	key := Service4Key{
		Port:        port,
		Proto:       uint8(proto),
		Scope:       scope,
		BackendSlot: slot,
	}

	copy(key.Address[:], ip.To4())

	return &key
}

func (k *Service4Key) New() bpf.MapKey { return &Service4Key{} }

func (k *Service4Key) Map() *bpf.Map { return Service4MapV2 }

// ToHost converts Service4Key to host byte order.
func (k *Service4Key) ToHost() ServiceKey {
	h := *k
	h.Port = byteorder.NetworkToHost16(h.Port)
	return &h
}

func (k *Service4Key) String() string {
	kHost := k.ToHost().(*Service4Key)
	addr := net.JoinHostPort(kHost.Address.String(), fmt.Sprintf("%d", kHost.Port))
	//if kHost.Scope == loadbalancer.ScopeInternal {
	//	addr += "/i"
	//}
	return addr
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

func (s *Service4Value) New() bpf.MapValue { return &Service4Value{} }

func (s *Service4Value) String() string {
	sHost := s.ToHost().(*Service4Value)
	return fmt.Sprintf("%d %d (%d) [0x%x 0x%x]", sHost.BackendID, sHost.Count, sHost.RevNat, sHost.Flags, sHost.Flags2)
}

// ToHost converts Service4Value to host byte order.
func (s *Service4Value) ToHost() ServiceValue {
	h := *s
	h.RevNat = byteorder.NetworkToHost16(h.RevNat)
	return &h
}

// params InitParams
func initSVC() {
	Service4MapV2 = bpf.NewMap(Service4MapV2Name,
		ebpf.Hash,
		&Service4Key{},
		&Service4Value{},
		65535, //ServiceMapMaxEntries,
		0,
	)
}
