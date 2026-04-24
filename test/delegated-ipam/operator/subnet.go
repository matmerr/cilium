// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/ipam/cidrset"
)

// SubnetAllocator carves fixed /24 subnets from a parent CIDR.
// It wraps Cilium's cidrset.CidrSet with node-name tracking.
type SubnetAllocator struct {
	mu        sync.Mutex
	cidrSet   *cidrset.CidrSet
	parentNet *net.IPNet
	// allocated maps node name → /24 CIDR string.
	allocated map[string]string
}

// NewSubnetAllocator creates an allocator from a parent CIDR (e.g. "10.0.0.0/16").
// The parent must have a prefix length ≤ 24 so at least one /24 fits.
func NewSubnetAllocator(parentCIDR string) (*SubnetAllocator, error) {
	_, parentNet, err := net.ParseCIDR(parentCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid parent CIDR %q: %w", parentCIDR, err)
	}

	ones, bits := parentNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 is supported, got %d-bit address", bits)
	}
	if ones > 24 {
		return nil, fmt.Errorf("parent CIDR /%d is too small for /24 subnets", ones)
	}

	cs, err := cidrset.NewCIDRSet(parentNet, 24)
	if err != nil {
		return nil, fmt.Errorf("creating CIDR set: %w", err)
	}

	return &SubnetAllocator{
		cidrSet:   cs,
		parentNet: parentNet,
		allocated: make(map[string]string),
	}, nil
}

// Allocate assigns the next free /24 to the named node. If the node already
// has an allocation, the existing subnet is returned.
func (a *SubnetAllocator) Allocate(nodeName string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if cidr, ok := a.allocated[nodeName]; ok {
		return cidr, nil
	}

	subnet, err := a.cidrSet.AllocateNext()
	if err != nil {
		return "", fmt.Errorf("no free /24 subnets in %s: %w", a.parentNet.String(), err)
	}

	cidr := subnet.String()
	a.allocated[nodeName] = cidr
	return cidr, nil
}

// Release frees the /24 allocated to the named node.
func (a *SubnetAllocator) Release(nodeName string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	cidr, ok := a.allocated[nodeName]
	if !ok {
		return
	}

	_, subnet, err := net.ParseCIDR(cidr)
	if err == nil {
		a.cidrSet.Release(subnet)
	}
	delete(a.allocated, nodeName)
}

// Get returns the /24 CIDR for a node, or "" if unallocated.
func (a *SubnetAllocator) Get(nodeName string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.allocated[nodeName]
}

// LoadExisting restores a previously allocated node→subnet mapping.
// Used on operator restart to rebuild state from CRD status.
func (a *SubnetAllocator) LoadExisting(nodeName, cidr string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	_, subnetNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid subnet %q: %w", cidr, err)
	}

	if err := a.cidrSet.Occupy(subnetNet); err != nil {
		return fmt.Errorf("occupying subnet %s: %w", cidr, err)
	}

	a.allocated[nodeName] = cidr
	return nil
}

// GatewayIP returns the first usable IP in a /24 subnet (the .1 address).
func GatewayIP(subnetCIDR string) (string, error) {
	ip, _, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid subnet %q: %w", subnetCIDR, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not an IPv4 address: %s", ip)
	}
	gw := make(net.IP, 4)
	copy(gw, ip4)
	gw[3] = 1
	return gw.String(), nil
}
