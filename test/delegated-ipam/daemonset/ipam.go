// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package daemonset

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
)

// IPAllocator wraps ipallocator.Range with container-ID tracking.
// Range allocates by IP; this adds the containerID→IP index needed by CNI.
type IPAllocator struct {
	mu      sync.Mutex
	r       *ipallocator.Range
	subnet  *net.IPNet
	gateway net.IP
	byID    map[string]net.IP
}

// NewIPAllocator creates an allocator for the given CIDR, reserving the gateway (.1).
func NewIPAllocator(subnetCIDR string) (*IPAllocator, error) {
	_, subnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet %q: %w", subnetCIDR, err)
	}

	r := ipallocator.NewCIDRRange(subnet)

	// Reserve the gateway (.1).
	gw := make(net.IP, len(subnet.IP))
	copy(gw, subnet.IP)
	gw = gw.To4()
	gw[3] = 1
	if err := r.Allocate(gw); err != nil {
		return nil, fmt.Errorf("reserving gateway %s: %w", gw, err)
	}

	return &IPAllocator{
		r:       r,
		subnet:  subnet,
		gateway: gw,
		byID:    make(map[string]net.IP),
	}, nil
}

// Allocate assigns the next free IP to the container. Idempotent.
func (a *IPAllocator) Allocate(containerID string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip, ok := a.byID[containerID]; ok {
		return ip, nil
	}

	ip, err := a.r.AllocateNext()
	if err != nil {
		return nil, fmt.Errorf("no free IPs in %s: %w", a.subnet, err)
	}
	a.byID[containerID] = ip
	return ip, nil
}

// Release frees the IP held by the container.
func (a *IPAllocator) Release(containerID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	ip, ok := a.byID[containerID]
	if !ok {
		return false
	}
	a.r.Release(ip)
	delete(a.byID, containerID)
	return true
}

// Has returns true if the container has an allocation.
func (a *IPAllocator) Has(containerID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.byID[containerID]
	return ok
}

// Get returns the IP for a container, or nil.
func (a *IPAllocator) Get(containerID string) net.IP {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.byID[containerID]
}

// Gateway returns the gateway IP.
func (a *IPAllocator) Gateway() net.IP { return a.gateway }

// Subnet returns the subnet CIDR.
func (a *IPAllocator) Subnet() *net.IPNet { return a.subnet }

// Available returns the number of free IPs.
func (a *IPAllocator) Available() int { return a.r.Free() }
