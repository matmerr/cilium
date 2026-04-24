// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cni

import (
	cniTypes "github.com/containernetworking/cni/pkg/types"
)

// NetConf is the CNI network configuration for the delegated test plugin.
type NetConf struct {
	cniTypes.NetConf

	// SocketPath overrides the default Unix socket for the IPAM DaemonSet.
	SocketPath string `json:"socketPath,omitempty"`
}

// AllocateRequest is sent to the DaemonSet to request an IP.
type AllocateRequest struct {
	ContainerID  string `json:"containerID"`
	IfName       string `json:"ifName"`
	Netns        string `json:"netns"`
	PodName      string `json:"podName,omitempty"`
	PodNamespace string `json:"podNamespace,omitempty"`
}

// AllocateResponse is returned by the DaemonSet.
type AllocateResponse struct {
	IP      string `json:"ip"`
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway"`
}

// ReleaseRequest is sent to release an IP.
type ReleaseRequest struct {
	ContainerID  string `json:"containerID"`
	PodName      string `json:"podName,omitempty"`
	PodNamespace string `json:"podNamespace,omitempty"`
}

// CheckRequest is sent to verify an allocation exists.
type CheckRequest struct {
	ContainerID  string `json:"containerID"`
	IfName       string `json:"ifName"`
	PodName      string `json:"podName,omitempty"`
	PodNamespace string `json:"podNamespace,omitempty"`
}
