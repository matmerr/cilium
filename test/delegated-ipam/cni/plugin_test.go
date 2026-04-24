// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cni

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
)

// ciliumConflist mirrors the real 05-cilium.conflist that Cilium generates
// when ipam.mode=delegated-plugin is configured. The IPAM plugin section
// is what Cilium extracts and passes to DelegateAdd.
const ciliumConflist = `{
  "cniVersion": "0.3.1",
  "name": "cilium",
  "plugins": [
    {
      "type": "cilium-cni",
      "enable-debug": true,
      "log-file": "/var/log/cilium-cni.log",
      "ipam": {
        "type": "cilium-delegated-ipam"
      }
    }
  ]
}`

// ipamPluginConf is the config that Cilium passes to DelegateAdd — the IPAM
// plugin section extracted from the conflist above, with top-level CNI fields.
const ipamPluginConf = `{
  "cniVersion": "0.3.1",
  "name": "cilium",
  "type": "cilium-delegated-ipam"
}`

// cniArgs simulates the K8S_POD_NAME/K8S_POD_NAMESPACE that kubelet sets.
const cniArgs = "K8S_POD_NAME=nginx-abc123;K8S_POD_NAMESPACE=default;K8S_POD_INFRA_CONTAINER_ID=deadbeef"

func newTestPlugin(t *testing.T, srv *httptest.Server) *Plugin {
	t.Helper()
	return &Plugin{httpClient: &http.Client{
		Transport: &testTransport{server: srv},
	}}
}

func newAllocateServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/allocate", func(w http.ResponseWriter, r *http.Request) {
		var req AllocateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.ContainerID == "" {
			http.Error(w, "missing containerID", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(AllocateResponse{
			IP:      "10.244.1.42",
			Subnet:  "10.244.1.0/24",
			Gateway: "10.244.1.1",
		})
	})
	return httptest.NewServer(mux)
}

func newReleaseServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/release", func(w http.ResponseWriter, r *http.Request) {
		var req ReleaseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
}

func newCheckServer(t *testing.T, knownContainers map[string]bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		var req CheckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !knownContainers[req.ContainerID] {
			http.Error(w, "allocation not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
}

func TestAllocate(t *testing.T) {
	srv := newAllocateServer(t)
	defer srv.Close()
	p := newTestPlugin(t, srv)

	args := &skel.CmdArgs{
		ContainerID: "abc123",
		IfName:      "eth0",
		Netns:       "/var/run/netns/test",
		Args:        cniArgs,
		StdinData:   []byte(ipamPluginConf),
	}

	if err := p.Add(args); err != nil {
		t.Fatalf("Add: %v", err)
	}
}

func TestAllocateParsesPodInfo(t *testing.T) {
	var captured AllocateRequest
	mux := http.NewServeMux()
	mux.HandleFunc("/allocate", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		json.NewEncoder(w).Encode(AllocateResponse{
			IP: "10.244.1.42", Subnet: "10.244.1.0/24", Gateway: "10.244.1.1",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	p := newTestPlugin(t, srv)

	args := &skel.CmdArgs{
		ContainerID: "abc123",
		IfName:      "eth0",
		Netns:       "/var/run/netns/test",
		Args:        cniArgs,
		StdinData:   []byte(ipamPluginConf),
	}
	if err := p.Add(args); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if captured.PodName != "nginx-abc123" {
		t.Errorf("PodName = %q, want %q", captured.PodName, "nginx-abc123")
	}
	if captured.PodNamespace != "default" {
		t.Errorf("PodNamespace = %q, want %q", captured.PodNamespace, "default")
	}
}

func TestRelease(t *testing.T) {
	srv := newReleaseServer(t)
	defer srv.Close()
	p := newTestPlugin(t, srv)

	args := &skel.CmdArgs{
		ContainerID: "abc123",
		IfName:      "eth0",
		Args:        cniArgs,
		StdinData:   []byte(ipamPluginConf),
	}

	if err := p.Del(args); err != nil {
		t.Fatalf("Del: %v", err)
	}
}

func TestCheckFound(t *testing.T) {
	srv := newCheckServer(t, map[string]bool{"abc123": true})
	defer srv.Close()
	p := newTestPlugin(t, srv)

	args := &skel.CmdArgs{
		ContainerID: "abc123",
		IfName:      "eth0",
		Args:        cniArgs,
		StdinData:   []byte(ipamPluginConf),
	}
	if err := p.Check(args); err != nil {
		t.Fatalf("Check existing: %v", err)
	}
}

func TestCheckNotFound(t *testing.T) {
	srv := newCheckServer(t, map[string]bool{})
	defer srv.Close()
	p := newTestPlugin(t, srv)

	args := &skel.CmdArgs{
		ContainerID: "missing",
		IfName:      "eth0",
		StdinData:   []byte(ipamPluginConf),
	}
	if err := p.Check(args); err == nil {
		t.Error("Check missing: expected error")
	}
}

func TestLoadConf(t *testing.T) {
	conf, err := loadConf([]byte(ipamPluginConf))
	if err != nil {
		t.Fatalf("loadConf: %v", err)
	}
	if conf.CNIVersion != "0.3.1" {
		t.Errorf("CNIVersion = %s, want 0.3.1", conf.CNIVersion)
	}
	if conf.Name != "cilium" {
		t.Errorf("Name = %s, want cilium", conf.Name)
	}
	if conf.Type != "cilium-delegated-ipam" {
		t.Errorf("Type = %s, want cilium-delegated-ipam", conf.Type)
	}
}

func TestLoadConfWithSocketPath(t *testing.T) {
	data := []byte(`{
		"cniVersion": "0.3.1",
		"name": "cilium",
		"type": "cilium-delegated-ipam",
		"socketPath": "/var/run/custom.sock"
	}`)
	conf, err := loadConf(data)
	if err != nil {
		t.Fatalf("loadConf: %v", err)
	}
	if conf.SocketPath != "/var/run/custom.sock" {
		t.Errorf("SocketPath = %s, want /var/run/custom.sock", conf.SocketPath)
	}
}

func TestLoadConfInvalid(t *testing.T) {
	_, err := loadConf([]byte("not-json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// testTransport redirects all requests to the test server.
type testTransport struct {
	server *httptest.Server
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
