// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/cilium/cilium/test/delegated-ipam/api"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// Controller watches Kubernetes nodes and manages subnet allocations
// in the CiliumTestIPAM CRD.
type Controller struct {
	mu           sync.Mutex
	kubeClient   kubernetes.Interface
	ipamClient   *api.Client
	allocator    *SubnetAllocator
	parentSubnet string
	crdName      string
}

// NewController creates a new operator controller.
func NewController(
	kubeClient kubernetes.Interface,
	ipamClient *api.Client,
	parentSubnet string,
) (*Controller, error) {
	alloc, err := NewSubnetAllocator(parentSubnet)
	if err != nil {
		return nil, fmt.Errorf("creating subnet allocator: %w", err)
	}

	return &Controller{
		kubeClient:   kubeClient,
		ipamClient:   ipamClient,
		allocator:    alloc,
		parentSubnet: parentSubnet,
		crdName:      api.CRDName,
	}, nil
}

// handleNode ensures a /24 subnet is allocated for the given node.
func (c *Controller) handleNode(ctx context.Context, node *corev1.Node) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nodeName := node.Name

	if existing := c.allocator.Get(nodeName); existing != "" {
		return
	}

	subnet, err := c.allocator.Allocate(nodeName)
	if err != nil {
		log.Printf("Error allocating subnet for node %s: %v", nodeName, err)
		return
	}

	gateway, err := GatewayIP(subnet)
	if err != nil {
		log.Printf("Error computing gateway for %s: %v", subnet, err)
		return
	}

	nodeStatus := api.NodeIPAMStatus{
		Subnet:   subnet,
		Gateway:  gateway,
		Capacity: 253,
	}

	if err := c.ipamClient.PatchNodeStatus(ctx, c.crdName, nodeName, nodeStatus); err != nil {
		log.Printf("Error patching CRD status for node %s: %v", nodeName, err)
		c.allocator.Release(nodeName)
		return
	}

	log.Printf("Allocated subnet %s for node %s (gateway: %s, capacity: 253)", subnet, nodeName, gateway)
}

// loadExistingAllocations reads the CRD and rebuilds the allocator state.
func (c *Controller) loadExistingAllocations(ctx context.Context) error {
	ipam, err := c.ipamClient.Get(ctx, c.crdName)
	if err != nil {
		return fmt.Errorf("getting CiliumTestIPAM %q: %w", c.crdName, err)
	}

	if ipam.Name != api.CRDName {
		log.Printf("Warning: ignoring CiliumTestIPAM %q — only %q is supported", ipam.Name, api.CRDName)
		return nil
	}

	for nodeName, nodeStatus := range ipam.Status.Nodes {
		if err := c.allocator.LoadExisting(nodeName, nodeStatus.Subnet); err != nil {
			log.Printf("Warning: failed to load allocation for node %s: %v", nodeName, err)
		}
	}

	return nil
}

// HandleNodeForTest exposes handleNode for testing.
func (c *Controller) HandleNodeForTest(ctx context.Context, node *corev1.Node) {
	c.handleNode(ctx, node)
}
