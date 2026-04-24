// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

var gvr = schema.GroupVersionResource{
	Group:    GroupName,
	Version:  Version,
	Resource: ResourceName,
}

// Client provides typed access to CiliumTestIPAM resources using the dynamic client.
type Client struct {
	client dynamic.ResourceInterface
}

// NewClient creates a CiliumTestIPAM client from a rest.Config.
func NewClient(config *rest.Config) (*Client, error) {
	dc, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}
	return &Client{
		client: dc.Resource(gvr),
	}, nil
}

// NewClientFromDynamic creates a CiliumTestIPAM client from an existing dynamic interface.
func NewClientFromDynamic(dc dynamic.Interface) *Client {
	return &Client{
		client: dc.Resource(gvr),
	}
}

// Get retrieves the CiliumTestIPAM resource by name.
func (c *Client) Get(ctx context.Context, name string) (*CiliumTestIPAM, error) {
	obj, err := c.client.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return fromUnstructured(obj)
}

// Create creates a new CiliumTestIPAM resource.
func (c *Client) Create(ctx context.Context, ipam *CiliumTestIPAM) (*CiliumTestIPAM, error) {
	obj, err := toUnstructured(ipam)
	if err != nil {
		return nil, err
	}
	result, err := c.client.Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return fromUnstructured(result)
}

// PatchStatus performs a JSON merge patch on the status subresource.
// Only the status.nodes entry for the given node is affected.
func (c *Client) PatchStatus(ctx context.Context, name string, status CiliumTestIPAMStatus) error {
	patch := map[string]interface{}{
		"status": map[string]interface{}{
			"nodes": convertNodes(status.Nodes),
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshaling status patch: %w", err)
	}
	_, err = c.client.Patch(ctx, name, types.MergePatchType, patchBytes, metav1.PatchOptions{}, "status")
	return err
}

// PatchNodeStatus patches only a single node's status entry using merge patch.
// Used by the operator to set subnet, gateway, and capacity.
func (c *Client) PatchNodeStatus(ctx context.Context, crdName, nodeName string, nodeStatus NodeIPAMStatus) error {
	nodeData := map[string]interface{}{
		"subnet":   nodeStatus.Subnet,
		"gateway":  nodeStatus.Gateway,
		"capacity": nodeStatus.Capacity,
	}

	patch := map[string]interface{}{
		"status": map[string]interface{}{
			"nodes": map[string]interface{}{
				nodeName: nodeData,
			},
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshaling node status patch: %w", err)
	}
	_, err = c.client.Patch(ctx, crdName, types.MergePatchType, patchBytes, metav1.PatchOptions{}, "status")
	return err
}

func convertNodes(nodes map[string]NodeIPAMStatus) map[string]interface{} {
	result := make(map[string]interface{}, len(nodes))
	for k, v := range nodes {
		result[k] = map[string]interface{}{
			"subnet":   v.Subnet,
			"gateway":  v.Gateway,
			"capacity": v.Capacity,
		}
	}
	return result
}

func toUnstructured(ipam *CiliumTestIPAM) (*unstructured.Unstructured, error) {
	data, err := json.Marshal(ipam)
	if err != nil {
		return nil, fmt.Errorf("marshaling CiliumTestIPAM: %w", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, &obj.Object); err != nil {
		return nil, fmt.Errorf("unmarshaling to unstructured: %w", err)
	}
	return obj, nil
}

func fromUnstructured(obj *unstructured.Unstructured) (*CiliumTestIPAM, error) {
	data, err := json.Marshal(obj.Object)
	if err != nil {
		return nil, fmt.Errorf("marshaling unstructured: %w", err)
	}
	ipam := &CiliumTestIPAM{}
	if err := json.Unmarshal(data, ipam); err != nil {
		return nil, fmt.Errorf("unmarshaling CiliumTestIPAM: %w", err)
	}
	return ipam, nil
}
