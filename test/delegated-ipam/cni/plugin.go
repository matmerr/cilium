// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cni

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/test/delegated-ipam/api"
)

// Plugin implements the CNI operations.
type Plugin struct {
	httpClient *http.Client
}

// New creates a Plugin with a Unix socket HTTP client.
func New() *Plugin {
	return &Plugin{
		httpClient: newUnixClient(api.SocketPath),
	}
}

// NewWithSocket creates a Plugin using a custom socket path.
func NewWithSocket(socketPath string) *Plugin {
	return &Plugin{
		httpClient: newUnixClient(socketPath),
	}
}

// NewWithClient creates a Plugin with a custom HTTP client (for testing).
func NewWithClient(client *http.Client) *Plugin {
	return &Plugin{httpClient: client}
}

func newUnixClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
}

func loadConf(data []byte) (*NetConf, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, fmt.Errorf("failed to parse CNI config: %w", err)
	}
	return conf, nil
}

// parseCNIArgs extracts K8S_POD_NAME and K8S_POD_NAMESPACE from the
// semicolon-delimited CNI_ARGS string (e.g. "K8S_POD_NAME=foo;K8S_POD_NAMESPACE=bar").
func parseCNIArgs(args string) (podName, podNamespace string) {
	for _, part := range splitArgs(args) {
		if k, v, ok := cutArg(part); ok {
			switch k {
			case "K8S_POD_NAME":
				podName = v
			case "K8S_POD_NAMESPACE":
				podNamespace = v
			}
		}
	}
	return
}

func splitArgs(s string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ';' {
			if start < i {
				parts = append(parts, s[start:i])
			}
			start = i + 1
		}
	}
	return parts
}

func cutArg(s string) (key, value string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// Add handles CNI ADD — allocates an IP from the DaemonSet.
func (p *Plugin) Add(args *skel.CmdArgs) error {
	conf, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	podName, podNamespace := parseCNIArgs(args.Args)

	req := AllocateRequest{
		ContainerID:  args.ContainerID,
		IfName:       args.IfName,
		Netns:        args.Netns,
		PodName:      podName,
		PodNamespace: podNamespace,
	}

	var resp AllocateResponse
	if err := p.post("/allocate", req, &resp); err != nil {
		return fmt.Errorf("IPAM allocate failed: %w", err)
	}

	ip := net.ParseIP(resp.IP)
	if ip == nil {
		return fmt.Errorf("invalid IP from IPAM: %s", resp.IP)
	}

	_, subnetNet, err := net.ParseCIDR(resp.Subnet)
	if err != nil {
		return fmt.Errorf("invalid subnet from IPAM: %s", resp.Subnet)
	}

	gwIP := net.ParseIP(resp.Gateway)
	if gwIP == nil {
		return fmt.Errorf("invalid gateway from IPAM: %s", resp.Gateway)
	}

	ones, _ := subnetNet.Mask.Size()
	result := &cniTypesV1.Result{
		CNIVersion: conf.CNIVersion,
		IPs: []*cniTypesV1.IPConfig{
			{
				Address: net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(ones, 32),
				},
				Gateway: gwIP,
			},
		},
		Routes: []*cniTypes.Route{
			{
				Dst: net.IPNet{
					IP:   net.IPv4zero,
					Mask: net.CIDRMask(0, 32),
				},
				GW: gwIP,
			},
		},
	}

	return cniTypes.PrintResult(result, conf.CNIVersion)
}

// Del handles CNI DEL — releases the container's IP.
func (p *Plugin) Del(args *skel.CmdArgs) error {
	podName, podNamespace := parseCNIArgs(args.Args)
	req := ReleaseRequest{
		ContainerID:  args.ContainerID,
		PodName:      podName,
		PodNamespace: podNamespace,
	}
	return p.post("/release", req, nil)
}

// Check handles CNI CHECK — validates the allocation still exists.
func (p *Plugin) Check(args *skel.CmdArgs) error {
	podName, podNamespace := parseCNIArgs(args.Args)
	req := CheckRequest{
		ContainerID:  args.ContainerID,
		IfName:       args.IfName,
		PodName:      podName,
		PodNamespace: podNamespace,
	}
	return p.post("/check", req, nil)
}

func (p *Plugin) post(path string, body interface{}, response interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := p.httpClient.Post("http://localhost"+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("HTTP request to %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d: %s", path, resp.StatusCode, string(respBody))
	}

	if response != nil {
		if err := json.Unmarshal(respBody, response); err != nil {
			return fmt.Errorf("unmarshal response from %s: %w", path, err)
		}
	}

	return nil
}
