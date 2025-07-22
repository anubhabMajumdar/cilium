package dynamicsubnet

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"dynamic-subnet",
	"Provides dynamic subnet management for Cilium",

	cell.Invoke(NewConfigWatcher),
)

type SubnetTopologyParams struct {
	cell.In

	Logger          *slog.Logger
	DaemonConfig    *option.DaemonConfig
	MetricsRegistry *metrics.Registry
	Lifecycle       cell.Lifecycle
}
