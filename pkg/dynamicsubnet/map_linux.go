// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package dynamicsubnet

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// CIDR subnet map.
	MaxEntries = 1024

	// MapName is the canonical name for the CIDR subnet map on the filesystem.
	MapName = "cidr_subnet_map"
)

// LPMTrieKey implements the bpf.MapKey interface for LPM trie maps.
// Must be in sync with struct lpm_trie_key in <bpf/lib/subnet.h>
type LPMTrieKey struct {
	Prefixlen uint32    `align:"prefixlen"`
	Addr      [16]uint8 `align:"addr"`
}

// String provides a human-readable representation of the LPMTrieKey.
func (k *LPMTrieKey) String() string {
	var addr net.IP
	var prefixLen int

	if k.Prefixlen == 32 {
		// IPv4
		addr = net.IP(k.Addr[:4])
		prefixLen = 32
	} else if k.Prefixlen == 128 {
		// IPv6
		addr = net.IP(k.Addr[:])
		prefixLen = 128
	} else {
		// Custom prefix length
		if k.Prefixlen <= 32 {
			addr = net.IP(k.Addr[:4])
			prefixLen = int(k.Prefixlen)
		} else {
			addr = net.IP(k.Addr[:])
			prefixLen = int(k.Prefixlen)
		}
	}

	return fmt.Sprintf("%s/%d", addr.String(), prefixLen)
}

// New returns a pointer to a new LPMTrieKey.
func (k *LPMTrieKey) New() bpf.MapKey {
	return &LPMTrieKey{}
}

// NewLPMTrieKey creates a new LPMTrieKey from the given CIDR.
func NewLPMTrieKey(cidr *net.IPNet) *LPMTrieKey {
	key := &LPMTrieKey{}

	prefixLen, _ := cidr.Mask.Size()
	key.Prefixlen = uint32(prefixLen)

	if ipv4 := cidr.IP.To4(); ipv4 != nil {
		// IPv4 address
		copy(key.Addr[:4], ipv4)
		// Clear the rest of the bytes for IPv4
		for i := 4; i < 16; i++ {
			key.Addr[i] = 0
		}
	} else {
		// IPv6 address
		copy(key.Addr[:], cidr.IP.To16())
	}

	return key
}

// SubnetID represents the value stored in the CIDR subnet map.
type SubnetID uint32

// String provides a human-readable representation of the SubnetID.
func (s SubnetID) String() string {
	return fmt.Sprintf("%d", uint32(s))
}

// New returns a pointer to a new SubnetID.
func (s SubnetID) New() bpf.MapValue {
	return new(SubnetID)
}

// CIDRSubnetMap represents the CIDR subnet BPF map.
type CIDRSubnetMap struct {
	bpf.Map
	mu sync.RWMutex
}

// newCIDRSubnetMap creates a new BPF map for CIDR to subnet ID mapping.
func newCIDRSubnetMap(name string) *bpf.Map {
	return bpf.NewMap(
		name,
		ebpf.LPMTrie,
		&LPMTrieKey{},
		new(SubnetID),
		MaxEntries,
		unix.BPF_F_NO_PREALLOC)
}

// NewCIDRSubnetMap instantiates a new CIDRSubnetMap.
func NewCIDRSubnetMap(registry *metrics.Registry, name string) *CIDRSubnetMap {
	return &CIDRSubnetMap{
		Map: *newCIDRSubnetMap(name).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(name)),
	}
}

// createCIDRSubnetMap creates a new CIDR subnet map and ensures it's ready for use.
// This function creates the map, opens it (or creates it if it doesn't exist),
// and returns the initialized map instance.
func (c *CIDRSubnetMap) createCIDRSubnetMap() error {
	// Open or create the map in the BPF filesystem
	if err := c.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to open or create CIDR subnet map: %w", err)
	}

	return nil
}

var (
	// cidrSubnetMap is the singleton map instance
	cidrSubnetMap *CIDRSubnetMap
	once          = &sync.Once{}
)

// CIDRSubnetMapSingleton gets the CIDRSubnetMap singleton. If it has not already been done,
// this also initializes the Map.
func CIDRSubnetMapSingleton(registry *metrics.Registry) *CIDRSubnetMap {
	once.Do(func() {
		cidrSubnetMap = NewCIDRSubnetMap(registry, MapName)
	})
	return cidrSubnetMap
}

// UpdateCIDR adds or updates a CIDR to subnet ID mapping in the map.
func (m *CIDRSubnetMap) UpdateCIDR(cidr *net.IPNet, subnetID uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := NewLPMTrieKey(cidr)
	value := SubnetID(subnetID)

	return m.Update(key, &value)
}

// LookupCIDR looks up the subnet ID for a given IP address.
func (m *CIDRSubnetMap) LookupCIDR(ip net.IP) (uint32, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a key for the lookup with maximum prefix length
	key := &LPMTrieKey{}
	if ipv4 := ip.To4(); ipv4 != nil {
		// IPv4
		key.Prefixlen = 32
		copy(key.Addr[:4], ipv4)
		for i := 4; i < 16; i++ {
			key.Addr[i] = 0
		}
	} else {
		// IPv6
		key.Prefixlen = 128
		copy(key.Addr[:], ip.To16())
	}

	value, err := m.Lookup(key)
	if err != nil {
		return 0, err
	}

	subnetID, ok := value.(*SubnetID)
	if !ok {
		return 0, fmt.Errorf("unexpected value type in map lookup")
	}

	return uint32(*subnetID), nil
}

// DeleteCIDR removes a CIDR from the map.
func (m *CIDRSubnetMap) DeleteCIDR(cidr *net.IPNet) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := NewLPMTrieKey(cidr)
	return m.Delete(key)
}

// LoadSubnetTopology loads the subnet topology from the configuration into the BPF map.
func (m *CIDRSubnetMap) LoadSubnetTopology(topology *subnetTopology) error {
	if topology == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing entries first
	if err := m.DeleteAll(); err != nil {
		return fmt.Errorf("failed to clear existing entries: %w", err)
	}

	// Add all subnets from the topology
	for _, subnet := range topology.subnets {
		key := NewLPMTrieKey(subnet.cidr)
		value := SubnetID(subnet.id)

		if err := m.Update(key, &value); err != nil {
			return fmt.Errorf("failed to update CIDR %s with subnet ID %d: %w",
				subnet.cidr.String(), subnet.id, err)
		}
	}

	return nil
}

// GetSubnetIDForIP returns the subnet ID for a given IP address using longest prefix match.
func (m *CIDRSubnetMap) GetSubnetIDForIP(ip netip.Addr) (uint32, error) {
	netIP := net.IP(ip.AsSlice())
	return m.LookupCIDR(netIP)
}
