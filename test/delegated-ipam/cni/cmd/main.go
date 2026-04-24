// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package main is the CNI plugin binary for delegated IPAM testing.
// It is installed by the DaemonSet onto the host filesystem.
package main

import (
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	cniVersion "github.com/containernetworking/cni/pkg/version"

	"github.com/cilium/cilium/test/delegated-ipam/cni"
)

func main() {
	runtime.LockOSThread()

	p := cni.New()
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   p.Add,
		Del:   p.Del,
		Check: p.Check,
	}, cniVersion.PluginSupports("0.3.0", "0.3.1", "0.4.0", "1.0.0"),
		"cilium-delegated-test-cni")
}
