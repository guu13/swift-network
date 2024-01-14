package bpf

import (
	"fmt"
	"path"
	"reflect"
	"time"

	"github.com/cilium/ebpf"
)

type MapKey interface {
	fmt.Stringer

	// New must return a pointer to a new MapKey.
	New() MapKey
}

type MapValue interface {
	fmt.Stringer

	// New must return a pointer to a new MapValue.
	New() MapValue
}

type Map struct {
	m *ebpf.Map
	// spec will be nil after the map has been created
	spec *ebpf.MapSpec

	key   MapKey
	value MapValue

	name string
	path string
	//lock lock.RWMutex

	// cachedCommonName is the common portion of the name excluding any
	// endpoint ID
	cachedCommonName string

	// enableSync is true when synchronization retries have been enabled.
	enableSync bool

	// withValueCache is true when map cache has been enabled
	withValueCache bool

	// cache as key/value entries when map cache is enabled or as key-only when
	// pressure metric is enabled
	//cache map[string]*cacheEntry

	// errorResolverLastScheduled is the timestamp when the error resolver
	// was last scheduled
	errorResolverLastScheduled time.Time

	// outstandingErrors states whether there are outstanding errors, occurred while
	// syncing an entry with the kernel, that need to be resolved. This variable exists
	// to avoid iterating over the full cache to check if reconciliation is necessary,
	// but it is possible that it gets out of sync if an error is automatically
	// resolved while performing a subsequent Update/Delete operation on the same key.
	outstandingErrors bool

	// pressureGauge is a metric that tracks the pressure on this map
	//pressureGauge *metrics.GaugeWithThreshold

	// is true when events buffer is enabled.
	eventsBufferEnabled bool

	// contains optional event buffer which stores last n bpf map events.
	//events *eventsBuffer
}

// NewMap creates a new Map instance - object representing a BPF map
func NewMap(name string, mapType ebpf.MapType, mapKey MapKey, mapValue MapValue,
	maxEntries int, flags uint32) *Map {

	keySize := reflect.TypeOf(mapKey).Elem().Size()
	valueSize := reflect.TypeOf(mapValue).Elem().Size()

	return &Map{
		spec: &ebpf.MapSpec{
			Type:       mapType,
			Name:       path.Base(name),
			KeySize:    uint32(keySize),
			ValueSize:  uint32(valueSize),
			MaxEntries: uint32(maxEntries),
			Flags:      flags,
		},
		name:  path.Base(name),
		key:   mapKey,
		value: mapValue,
	}
}

// OpenOrCreate attempts to open the Map, or if it does not yet exist, create
// the Map. If the existing map's attributes such as map type, key/value size,
// capacity, etc. do not match the Map's attributes, then the map will be
// deleted and reopened without any attempt to retain its previous contents.
// If the map is marked as non-persistent, it will always be recreated.
//
// Returns whether the map was deleted and recreated, or an optional error.
func (m *Map) OpenOrCreate() error {
	return m.openOrCreate(true)
}

func (m *Map) openOrCreate(pin bool) error {
	if m.m != nil {
		return nil
	}

	if m.spec == nil {
		return fmt.Errorf("attempted to create map %s without MapSpec", m.name)
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	m.spec.Flags |= (1 << 0) //GetPreAllocateMapFlags(m.spec.Type)

	if pin {
		m.spec.Pinning = ebpf.PinByName
	}

	em, err := OpenOrCreateMap(m.spec, path.Dir(m.path))
	if err != nil {
		return err
	}

	//把open的Map在内存中存下来
	//registerMap(m.path, m)

	// Consume the MapSpec.
	m.spec = nil

	// Retain the Map.
	m.m = em

	return nil
}

func (m *Map) setPathIfUnset() error {
	if m.path == "" {
		if m.name == "" {
			return fmt.Errorf("either path or name must be set")
		}

		//m.path = MapPath(m.name)
		m.path = "/sys/fs/bpf/tc/globals/" + m.name
	}

	return nil
}
