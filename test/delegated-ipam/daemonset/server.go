// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package daemonset

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/cilium/cilium/test/delegated-ipam/api"
	cni "github.com/cilium/cilium/test/delegated-ipam/cni"
)

// Server is the IPAM DaemonSet HTTP server. It reads the CiliumTestIPAM CRD
// to learn its node's subnet, then serves allocate/release/check/healthz endpoints.
type Server struct {
	nodeName  string
	allocator *IPAllocator
	crdName   string
	mu        sync.RWMutex
	ready     bool
	listener  net.Listener
	server    *http.Server
}

// NewServer creates a new IPAM server for the given node.
func NewServer(nodeName string) *Server {
	return &Server{
		nodeName: nodeName,
		crdName:  api.CRDName,
	}
}

// Configure sets up the allocator from CRD status.
func (s *Server) Configure(nodeStatus api.NodeIPAMStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alloc, err := NewIPAllocator(nodeStatus.Subnet)
	if err != nil {
		return fmt.Errorf("creating IP allocator for %s: %w", nodeStatus.Subnet, err)
	}
	s.allocator = alloc
	s.ready = true
	return nil
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/allocate", s.handleAllocate)
	mux.HandleFunc("/release", s.handleRelease)
	mux.HandleFunc("/check", s.handleCheck)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

// ListenAndServeUnix starts the server on a Unix socket.
func (s *Server) ListenAndServeUnix(socketPath string) error {
	// Remove stale socket
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	s.listener = listener

	s.server = &http.Server{Handler: s.Handler()}
	log.Printf("IPAM server listening on %s for node %s", socketPath, s.nodeName)
	return s.server.Serve(listener)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleAllocate(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	alloc := s.allocator
	ready := s.ready
	s.mu.RUnlock()

	if !ready {
		http.Error(w, "IPAM not ready", http.StatusServiceUnavailable)
		return
	}

	var req cni.AllocateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.ContainerID == "" {
		http.Error(w, "containerID is required", http.StatusBadRequest)
		return
	}

	podID := formatPodID(req.PodNamespace, req.PodName)

	if alloc == nil {
		http.Error(w, "IPAM not configured", http.StatusServiceUnavailable)
		return
	}

	ip, err := alloc.Allocate(req.ContainerID)
	if err != nil {
		log.Printf("[ADD] %s container=%s — FAILED: %v", podID, short(req.ContainerID), err)
		http.Error(w, "allocation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := cni.AllocateResponse{
		IP:      ip.String(),
		Subnet:  alloc.Subnet().String(),
		Gateway: alloc.Gateway().String(),
	}

	log.Printf("[ADD] %s container=%s → ip=%s subnet=%s gw=%s",
		podID, short(req.ContainerID), resp.IP, resp.Subnet, resp.Gateway)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	alloc := s.allocator
	ready := s.ready
	s.mu.RUnlock()

	if !ready {
		http.Error(w, "IPAM not ready", http.StatusServiceUnavailable)
		return
	}

	var req cni.ReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	podID := formatPodID(req.PodNamespace, req.PodName)
	var releasedIP string
	if alloc != nil {
		if ip := alloc.Get(req.ContainerID); ip != nil {
			releasedIP = ip.String()
		}
		alloc.Release(req.ContainerID)
	}
	if releasedIP != "" {
		log.Printf("[DEL] %s container=%s ip=%s — released", podID, short(req.ContainerID), releasedIP)
	} else {
		log.Printf("[DEL] %s container=%s — not found (already released)", podID, short(req.ContainerID))
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	alloc := s.allocator
	ready := s.ready
	s.mu.RUnlock()

	if !ready {
		http.Error(w, "IPAM not ready", http.StatusServiceUnavailable)
		return
	}

	var req cni.CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	podID := formatPodID(req.PodNamespace, req.PodName)
	found := alloc != nil && alloc.Has(req.ContainerID)

	if !found {
		log.Printf("[CHECK] %s container=%s — NOT FOUND", podID, short(req.ContainerID))
		http.Error(w, "allocation not found", http.StatusNotFound)
		return
	}

	log.Printf("[CHECK] %s container=%s — ok", podID, short(req.ContainerID))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ready := s.ready
	s.mu.RUnlock()

	if !ready {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// formatPodID returns "namespace/name" or "unknown" if pod info is missing.
func formatPodID(namespace, name string) string {
	if name == "" {
		return "pod=unknown"
	}
	if namespace == "" {
		namespace = "default"
	}
	return namespace + "/" + name
}

// short truncates a container ID to 12 chars for readable logs.
func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
