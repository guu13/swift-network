// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64

package cgroup_socklb

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	CgroupConnect4Svc2pod     *ebpf.ProgramSpec `ebpf:"cgroup_connect4_svc2pod"`
	CgroupGetpeername4Pod2svc *ebpf.ProgramSpec `ebpf:"cgroup_getpeername4_pod2svc"`
	CgroupSendmsg4Svc2pod     *ebpf.ProgramSpec `ebpf:"cgroup_sendmsg4_svc2pod"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	SnLb4PodMap *ebpf.MapSpec `ebpf:"sn_lb4_pod_map"`
	SnLb4SvcMap *ebpf.MapSpec `ebpf:"sn_lb4_svc_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	SnLb4PodMap *ebpf.Map `ebpf:"sn_lb4_pod_map"`
	SnLb4SvcMap *ebpf.Map `ebpf:"sn_lb4_svc_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.SnLb4PodMap,
		m.SnLb4SvcMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	CgroupConnect4Svc2pod     *ebpf.Program `ebpf:"cgroup_connect4_svc2pod"`
	CgroupGetpeername4Pod2svc *ebpf.Program `ebpf:"cgroup_getpeername4_pod2svc"`
	CgroupSendmsg4Svc2pod     *ebpf.Program `ebpf:"cgroup_sendmsg4_svc2pod"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.CgroupConnect4Svc2pod,
		p.CgroupGetpeername4Pod2svc,
		p.CgroupSendmsg4Svc2pod,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfeb.o
var _BpfBytes []byte
