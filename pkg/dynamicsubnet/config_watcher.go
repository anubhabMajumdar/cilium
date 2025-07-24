package dynamicsubnet

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"log/slog"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/hive/cell"
	"sigs.k8s.io/yaml"
)

type configWatcher struct {
	logger         *slog.Logger
	configFilePath string

	subnetTopology string
	hash           uint64

	cm *CIDRSubnetMap
}

// NewConfigWatcher returns a new configWatcher that monitors the specified configuration file.
func NewConfigWatcher(params SubnetTopologyParams) error {
	if params.DaemonConfig == nil || params.DaemonConfig.SubnetTopologyFilePath == "" {
		params.Logger.Info("No subnet topology file path provided, skipping config watcher initialization")
		return nil // No config watcher needed
	}
	params.Logger.Info("Initializing config watcher", "configFilePath", params.DaemonConfig.SubnetTopologyFilePath)
	// Create a new config watcher with the provided parameters.
	cw := &configWatcher{
		logger: params.Logger.With(
			logfields.LogSubsys, "dynamicsubnet",
			logfields.ConfigFile, params.DaemonConfig.SubnetTopologyFilePath+"/"+params.DaemonConfig.SubnetTopologyFileName,
		),
		configFilePath: params.DaemonConfig.SubnetTopologyFilePath + "/" + params.DaemonConfig.SubnetTopologyFileName,
		subnetTopology: "",
		cm:             CIDRSubnetMapSingleton(params.MetricsRegistry),
	}
	cw.logger.Info("Config watcher created")
	ctx, cancel := context.WithCancel(context.Background())
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			cw.logger.Info("Initialing the ebpf map for subnet topology")
			if err := cw.cm.createCIDRSubnetMap(); err != nil {
				cw.logger.Error("Failed to create CIDR subnet map", logfields.Error, err)
				return err
			}
			cw.logger.Info("CIDR subnet map created successfully")
			cw.logger.Info("Starting config watcher")
			go cw.watch(ctx, 5*time.Second)
			cw.logger.Info("Config watcher started", "interval", 5*time.Second)
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			cw.logger.Info("Stopping config watcher")
			cancel()
			return nil
		},
	})
	return nil
}

func (cw *configWatcher) watch(ctx context.Context, interval time.Duration) {
	cw.logger.Info("Starting config watcher", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			cw.logger.Info("Config watcher stopped")
			return
		case <-ticker.C:
			cw.reload()
		}
	}
}

func (cw *configWatcher) reload() {
	cw.logger.Info("Reloading configuration")
	curTopology, h, updated, err := cw.parse()
	if err != nil {
		cw.logger.Error("failed to reload config", logfields.Error, err)
		return
	}
	cw.logger.Info("Configuration reloaded successfully", "subnet-topology", curTopology, "hash", h)
	if curTopology == "" {
		cw.logger.Info("No configuration changes detected, skipping update")
		return
	}

	if !updated {
		cw.logger.Info("Configuration hash has not changed, skipping update")
		return
	}

	// New config is available, trigger topology sync.
	t, err := newTopology(curTopology)
	if err != nil {
		cw.logger.Error("failed to create subnet topology", logfields.Error, err)
		return
	}
	// Log the new topology for debugging.
	cw.logger.Info("New subnet topology created", "subnets", t.subnets)

	// Sync topology to the ebpf map.
	if err := cw.cm.LoadSubnetTopology(t); err != nil {
		cw.logger.Error("failed to load subnet topology into ebpf map", logfields.Error, err)
		return
	}

	// Sync completed, update the current config and hash.
	cw.subnetTopology = curTopology
	cw.hash = h
}

func calculateHash(file []byte) uint64 {
	sum := md5.Sum(file)
	return binary.LittleEndian.Uint64(sum[0:16])
}

func (cw *configWatcher) parse() (string, uint64, bool, error) {
	content, err := os.ReadFile(cw.configFilePath)
	if err != nil {
		cw.logger.Error("failed to read config file", logfields.Error, err)
		return "", 0, false, err
	}
	cw.logger.Info("Parsing configuration file", "content", string(content))

	h := calculateHash(content)
	if h == cw.hash {
		cw.logger.Info("Configuration hash has not changed, skipping reload")
		return cw.subnetTopology, cw.hash, false, nil
	}

	// Unmarshal the content into Config struct.
	var subnetTopology string
	// Assuming a YAML format for simplicity.
	if err := yaml.Unmarshal(content, &subnetTopology); err != nil {
		cw.logger.Error("failed to parse config file", logfields.Error, err)
		return "", 0, false, err
	}
	cw.logger.Info("Configuration parsed successfully", "subnet-topology", subnetTopology)
	return subnetTopology, h, true, nil
}
