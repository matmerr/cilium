// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package delegated

import (
	"context"
	"fmt"
	"net"

	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

// AllocateIPsWithDelegatedPlugin invokes the delegated IPAM plugin to allocate IPs.
// It returns the IPAM response, a release function to be called on failure, and any error.
// The release function should be called if the caller encounters an error after allocation
// to clean up the allocated IPs.
func AllocateIPsWithDelegatedPlugin(
	ctx context.Context,
	conf *models.DaemonConfigurationStatus,
	netConf *cnitypes.NetConf,
	stdinData []byte,
) (*models.IPAMResponse, func(context.Context), error) {
	ipamRawResult, err := cniInvoke.DelegateAdd(ctx, netConf.IPAM.Type, stdinData, nil)
	if err != nil {
		// Since IP allocation failed, there are no IPs to clean up, so we don't need to return a releaseFunc.
		return nil, nil, fmt.Errorf("failed to invoke delegated plugin ADD for IPAM: %w", err)
	}

	// CNI spec says if an error occurs, invoke DEL on the delegated plugin to release IPs.
	releaseFunc := func(ctx context.Context) {
		cniInvoke.DelegateDel(ctx, netConf.IPAM.Type, stdinData, nil)
	}

	ipamResult, err := cniTypesV1.NewResultFromResult(ipamRawResult)
	if err != nil {
		return nil, releaseFunc, fmt.Errorf("could not interpret delegated IPAM result for CNI version %s: %w", cniTypesV1.ImplementedSpecVersion, err)
	}

	// Translate the IPAM result into the same format as a response from Cilium agent.
	ipam := &models.IPAMResponse{
		HostAddressing: conf.Addressing,
		Address:        &models.AddressPair{},
	}

	// Safe to assume at most one IP per family. The K8s API docs say:
	// "Pods may be allocated at most 1 value for each of IPv4 and IPv6"
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/
	// Interface returned by IPAM should be treated as the uplink for the Pod as CNI spec introduced by:
	// https://github.com/containernetworking/cni/pull/1137
	masterMac := ""
	for _, iface := range ipamResult.Interfaces {
		if iface.Sandbox != "" {
			continue
		}

		if iface.Mac != "" {
			if ifMac, err := net.ParseMAC(iface.Mac); err != nil {
				return nil, releaseFunc, fmt.Errorf("failed to parse interface MAC %q: %w", iface.Mac, err)
			} else {
				masterMac = ifMac.String()
			}
		} else if iface.Name != "" {
			if uplink, err := safenetlink.LinkByName(iface.Name); err != nil {
				return nil, releaseFunc, fmt.Errorf("failed to get uplink %q: %w", iface.Name, err)
			} else {
				masterMac = uplink.Attrs().HardwareAddr.String()
			}
		}
		break
	}
	// Interface number could not be determined from IPAM result for now.
	// Set a static value zero before we have a proper solution.
	// option.Config.EgressMultiHomeIPRuleCompat also needs to be set to true.
	for _, ipConfig := range ipamResult.IPs {
		ipNet := ipConfig.Address
		if ipNet.IP.To4() != nil {
			if conf.Addressing.IPV4 != nil {
				ipam.Address.IPV4 = ipNet.String()
				ipam.IPV4 = &models.IPAMAddressResponse{
					IP:              ipNet.IP.String(),
					Gateway:         ipConfig.Gateway.String(),
					MasterMac:       masterMac,
					InterfaceNumber: "0",
				}
			}
		} else {
			if conf.Addressing.IPV6 != nil {
				ipam.Address.IPV6 = ipNet.String()
				ipam.IPV6 = &models.IPAMAddressResponse{
					IP:              ipNet.IP.String(),
					Gateway:         ipConfig.Gateway.String(),
					MasterMac:       masterMac,
					InterfaceNumber: "0",
				}
			}
		}
	}

	return ipam, releaseFunc, nil
}

// ReleaseIPsWithDelegatedPlugin releases IPs by calling DEL on the delegated IPAM plugin.
func ReleaseIPsWithDelegatedPlugin(ctx context.Context, netConf *cnitypes.NetConf, stdinData []byte) error {
	return cniInvoke.DelegateDel(ctx, netConf.IPAM.Type, stdinData, nil)
}
