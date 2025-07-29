package subnet

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/hive/cell"
)

const (
	MaxEntries = 1024 // Maximum number of entries in the subnet map
	Name       = "subnet_topology_map"
)

type SubnetKey struct {
	Prefixlen uint32     `align:"lpm_key"`
	IPV4      types.IPv4 `align:"ipv4"`
}

type SubnetValue struct {
	Identity uint32 `align:"identity"`
}

type SubnetTopology struct {
	Subnets map[SubnetKey]SubnetValue `align:"subnets"`

	m *bpf.Map

	l *slog.Logger
}

func (k *SubnetKey) String() string {
	// Unit32 to string conversion for logging
	return fmt.Sprintf("%s/%d", k.IPV4.String(), k.Prefixlen)
}

func (v *SubnetKey) New() bpf.MapKey {
	return &SubnetKey{}
}

func (v *SubnetValue) String() string {
	// Unit32 to string conversion for logging
	return fmt.Sprintf("Identity: %d", v.Identity)
}

func (v *SubnetValue) New() bpf.MapValue {
	return &SubnetValue{}
}

func newMap(name string) *bpf.Map {
	return bpf.NewMap(
		name,
		ebpf.LPMTrie,
		&SubnetKey{},
		&SubnetValue{},
		MaxEntries,
		0, // flags
	)
}

func createMap(lc cell.Lifecycle, registry *metrics.Registry) *SubnetTopology {
	m := newMap(Name).WithPressureMetric(registry)
	st := &SubnetTopology{
		Subnets: make(map[SubnetKey]SubnetValue),
		m:       m,
	}
	lc.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			// switch pinning {
			// case ebpf.PinNone:
			// 	return m.CreateUnpinned()
			// case ebpf.PinByName:
			// 	return m.OpenOrCreate()
			// }
			// return fmt.Errorf("unknown pinning type %s", pinning)
			if err := m.OpenOrCreate(); err != nil {
				return fmt.Errorf("failed to create BPF map %s: %w", Name, err)
			}
			st.l.Info("BPF map created", slog.String("name", Name))
			cidr := "10.244.0.0/16"
			// ip := net.ParseIP("10.244.0.0")
			// mask := net.IPMask{255, 255, 0, 0}
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("failed to parse CIDR %s: %w", cidr, err)
			}
			if ipnet == nil {
				return fmt.Errorf("failed to parse CIDR %s", cidr)
			}
			ip := ipnet.IP
			mask := ipnet.Mask
			if ip == nil || mask == nil {
				return fmt.Errorf("invalid CIDR %s", cidr)
			}
			key := NewSubnetKey(ip, mask)
			value := NewSubnetValue(1)
			if err := st.Add(key, value); err != nil {
				st.l.Error("Failed to add subnet", slog.String("key", key.String()), slog.String("error", err.Error()))
			}
			st.l.Info("Subnet added", slog.String("key", key.String()), slog.String("value", value.String()))
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			return m.Close()
		},
	})
	return st
}

func create(params Params) *SubnetTopology {
	st := createMap(params.Lifecycle, params.Registry)
	st.l = params.Logger.With(
		slog.String("module", "subnet_topology"),
		slog.String("name", Name),
	)
	return st
}

func (st *SubnetTopology) Add(key SubnetKey, value SubnetValue) error {
	if err := st.m.Update(&key, &value); err != nil {
		return fmt.Errorf("failed to add subnet %s: %w", key.String(), err)
	}
	st.Subnets[key] = value
	return nil
}

func NewSubnetKey(ip net.IP, mask net.IPMask) SubnetKey {
	prefixLen, _ := mask.Size()
	k := SubnetKey{
		Prefixlen: uint32(prefixLen),
	}
	copy(k.IPV4[:], ip.To4())
	return k
}

func NewSubnetValue(identity uint32) SubnetValue {
	return SubnetValue{
		Identity: identity,
	}
}

type Params struct {
	cell.In

	Logger    *slog.Logger
	Registry  *metrics.Registry
	Lifecycle cell.Lifecycle
}

var Cell = cell.Module(
	"subnet_topology",
	"Provides manager for subnet topology",
	cell.Invoke(create),
	// cell.Invoke(func(st *SubnetTopology) {
	// 	ip := net.ParseIP("10.244.0.0")
	// 	mask := net.IPMask{255, 255, 0, 0}
	// 	key := NewSubnetKey(ip, mask)
	// 	value := NewSubnetValue(1)
	// 	if err := st.Add(key, value); err != nil {
	// 		st.l.Error("Failed to add subnet", slog.String("key", key.String()), slog.String("error", err.Error()))
	// 	}
	// 	st.l.Info("Subnet added", slog.String("key", key.String()), slog.String("value", value.String()))
	// }),
)
