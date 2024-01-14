package lbmap

import "github.com/guu13/swift-network/pkg/bpf"

// ServiceKey is the interface describing protocol independent key for services map v2.
type ServiceKey interface {
	bpf.MapKey

	// Return the BPF map matching the key type
	Map() *bpf.Map

	// ToHost converts fields to host byte order.
	ToHost() ServiceKey
}

// ServiceValue is the interface describing protocol independent value for services map v2.
type ServiceValue interface {
	bpf.MapValue

	// ToHost converts fields to host byte order.
	ToHost() ServiceValue
}
