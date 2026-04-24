// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package daemonset

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/cilium/test/delegated-ipam/api"
	cni "github.com/cilium/cilium/test/delegated-ipam/cni"
)

func setupTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s := NewServer("test-node")
	err := s.Configure(api.NodeIPAMStatus{
		Subnet:  "10.0.0.0/24",
		Gateway: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return s, httptest.NewServer(s.Handler())
}

func TestServerAllocate(t *testing.T) {
	_, srv := setupTestServer(t)
	defer srv.Close()

	req := cni.AllocateRequest{ContainerID: "c1", IfName: "eth0"}
	body, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/allocate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /allocate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var allocResp cni.AllocateResponse
	json.NewDecoder(resp.Body).Decode(&allocResp)

	if allocResp.IP == "" || allocResp.IP == "10.0.0.0" || allocResp.IP == "10.0.0.1" || allocResp.IP == "10.0.0.255" {
		t.Errorf("IP = %s, want usable IP", allocResp.IP)
	}
	if allocResp.Gateway != "10.0.0.1" {
		t.Errorf("Gateway = %s, want 10.0.0.1", allocResp.Gateway)
	}
	if allocResp.Subnet != "10.0.0.0/24" {
		t.Errorf("Subnet = %s, want 10.0.0.0/24", allocResp.Subnet)
	}
}

func TestServerAllocateIdempotent(t *testing.T) {
	_, srv := setupTestServer(t)
	defer srv.Close()

	req := cni.AllocateRequest{ContainerID: "c1"}
	body, _ := json.Marshal(req)

	// Allocate twice
	resp1, _ := http.Post(srv.URL+"/allocate", "application/json", bytes.NewReader(body))
	var alloc1 cni.AllocateResponse
	json.NewDecoder(resp1.Body).Decode(&alloc1)
	resp1.Body.Close()

	resp2, _ := http.Post(srv.URL+"/allocate", "application/json", bytes.NewReader(body))
	var alloc2 cni.AllocateResponse
	json.NewDecoder(resp2.Body).Decode(&alloc2)
	resp2.Body.Close()

	if alloc1.IP != alloc2.IP {
		t.Errorf("idempotent failed: %s != %s", alloc1.IP, alloc2.IP)
	}
}

func TestServerRelease(t *testing.T) {
	_, srv := setupTestServer(t)
	defer srv.Close()

	// Allocate first
	allocReq := cni.AllocateRequest{ContainerID: "c1"}
	body, _ := json.Marshal(allocReq)
	http.Post(srv.URL+"/allocate", "application/json", bytes.NewReader(body))

	// Release
	relReq := cni.ReleaseRequest{ContainerID: "c1"}
	body, _ = json.Marshal(relReq)
	resp, err := http.Post(srv.URL+"/release", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /release: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestServerCheck(t *testing.T) {
	_, srv := setupTestServer(t)
	defer srv.Close()

	// Allocate
	allocReq := cni.AllocateRequest{ContainerID: "c1"}
	body, _ := json.Marshal(allocReq)
	http.Post(srv.URL+"/allocate", "application/json", bytes.NewReader(body))

	// Check existing
	checkReq := cni.CheckRequest{ContainerID: "c1", IfName: "eth0"}
	body, _ = json.Marshal(checkReq)
	resp, _ := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Check existing: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Check missing
	checkReq = cni.CheckRequest{ContainerID: "missing", IfName: "eth0"}
	body, _ = json.Marshal(checkReq)
	resp, _ = http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Check missing: expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerHealthz(t *testing.T) {
	// Not configured = not ready
	s := NewServer("test-node")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/healthz")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("unready healthz: expected 503, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Configure = ready
	s.Configure(api.NodeIPAMStatus{Subnet: "10.0.0.0/24"})
	resp, _ = http.Get(srv.URL + "/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ready healthz: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerNotReady(t *testing.T) {
	s := NewServer("test-node")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req := cni.AllocateRequest{ContainerID: "c1"}
	body, _ := json.Marshal(req)
	resp, _ := http.Post(srv.URL+"/allocate", "application/json", bytes.NewReader(body))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("allocate not ready: expected 503, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerAllocateEmptyContainerID(t *testing.T) {
	_, srv := setupTestServer(t)
	defer srv.Close()

	req := cni.AllocateRequest{ContainerID: ""}
	body, _ := json.Marshal(req)
	resp, _ := http.Post(srv.URL+"/allocate", "application/json", bytes.NewReader(body))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty containerID: expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
