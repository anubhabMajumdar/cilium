package dynamicsubnet

import (
	"fmt"
	"net"
	"strings"
)

type subnet struct {
	id int
	// CIDR is the CIDR of the subnet. Can be IPv4 or IPv6.
	cidr *net.IPNet
}

type subnetTopology struct {
	subnets []subnet
}

func newTopology(subnetConfig string) (*subnetTopology, error) {
	if subnetConfig == "" {
		return nil, fmt.Errorf("no subnet topology defined")
	}

	topology := &subnetTopology{}
	/*
		Parse the subnet topology from the configuration.
		Example format of subnetConfig:
		10.0.0.1/24,10.10.0.1/24;10.20.0.1/24;2001:0db8:85a3::/64
		Maps to subnets:
		| CIDR | Subnet ID |
		|------|-----------|
		| 10.0.0.1/24 | 1  |
		| 10.10.0.1/24 | 1 |
		| 10.20.0.1/24 | 2 |
		| 2001:0db8:85a3::/64 | 3 |
	*/

	// Split by semicolon to get groups (each group gets the same subnet ID)
	groups := strings.Split(subnetConfig, ";")

	for groupID, group := range groups {
		// Each group gets an ID starting from 1
		subnetID := groupID + 1

		// Split by comma to get individual CIDRs within the group
		cidrs := strings.SplitSeq(group, ",")

		for cidrStr := range cidrs {
			cidrStr = strings.TrimSpace(cidrStr)
			if cidrStr == "" {
				continue
			}

			// Parse the CIDR
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
			}

			// Add subnet to topology
			topology.subnets = append(topology.subnets, subnet{
				id:   subnetID,
				cidr: ipNet,
			})
		}
	}

	return topology, nil
}
