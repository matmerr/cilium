// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	fake2 "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/cilium/cilium/test/delegated-ipam/api"
)

// fakeDynamicServer mocks the Kubernetes API for CiliumTestIPAM.
type fakeDynamicServer struct {
	t       *testing.T
	patches []map[string]interface{}
	status  api.CiliumTestIPAMStatus
}

func newFakeDynamicServer(t *testing.T) (*fakeDynamicServer, *httptest.Server) {
	f := &fakeDynamicServer{
		t: t,
		status: api.CiliumTestIPAMStatus{
			Nodes: make(map[string]api.NodeIPAMStatus),
		},
	}

	mux := http.NewServeMux()

	// GET CiliumTestIPAM
	mux.HandleFunc("/apis/test.cilium.io/v1alpha1/ciliumtestipams/default", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			ipam := &api.CiliumTestIPAM{
				Spec: api.CiliumTestIPAMSpec{
					Subnet: "10.0.0.0/16",
				},
				Status: f.status,
			}
			ipam.SetName("default")
			ipam.SetGroupVersionKind(api.SchemeGroupVersion.WithKind("CiliumTestIPAM"))

			data, _ := json.Marshal(ipam)
			obj := &unstructured.Unstructured{}
			json.Unmarshal(data, &obj.Object)
			obj.SetAPIVersion("test.cilium.io/v1alpha1")
			obj.SetKind("CiliumTestIPAM")

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(obj.Object)
		}
	})

	// PATCH status subresource
	mux.HandleFunc("/apis/test.cilium.io/v1alpha1/ciliumtestipams/default/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			var patch map[string]interface{}
			json.NewDecoder(r.Body).Decode(&patch)
			f.patches = append(f.patches, patch)

			// Apply the patch to our status
			if statusData, ok := patch["status"].(map[string]interface{}); ok {
				if nodesData, ok := statusData["nodes"].(map[string]interface{}); ok {
					for nodeName, nodeData := range nodesData {
						nd := nodeData.(map[string]interface{})
						ns := api.NodeIPAMStatus{
							Subnet: nd["subnet"].(string),
						}
						if gw, ok := nd["gateway"].(string); ok {
							ns.Gateway = gw
						}
						if cap, ok := nd["capacity"].(float64); ok {
							ns.Capacity = int(cap)
						}
						f.status.Nodes[nodeName] = ns
					}
				}
			}

			// Return the "updated" object
			resp := map[string]interface{}{
				"apiVersion": "test.cilium.io/v1alpha1",
				"kind":       "CiliumTestIPAM",
				"metadata":   map[string]interface{}{"name": "default"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	})

	srv := httptest.NewServer(mux)
	return f, srv
}

func TestControllerHandleNode(t *testing.T) {
	_, srv := newFakeDynamicServer(t)
	defer srv.Close()

	dynClient, err := dynamic.NewForConfig(fakeRESTConfig(srv.URL))
	if err != nil {
		t.Fatalf("creating dynamic client: %v", err)
	}

	ipamClient := api.NewClientFromDynamic(dynClient)
	kubeClient := fake2.NewSimpleClientset()

	ctrl, err := NewController(kubeClient, ipamClient, "10.0.0.0/16")
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}

	ctx := context.Background()

	// Handle first node
	node1 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}
	ctrl.HandleNodeForTest(ctx, node1)

	if got := ctrl.allocator.Get("node-1"); got != "10.0.0.0/24" {
		t.Errorf("node-1 subnet = %s, want 10.0.0.0/24", got)
	}

	// Handle second node
	node2 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-2"}}
	ctrl.HandleNodeForTest(ctx, node2)

	if got := ctrl.allocator.Get("node-2"); got != "10.0.1.0/24" {
		t.Errorf("node-2 subnet = %s, want 10.0.1.0/24", got)
	}

	// Idempotent: handle node-1 again
	ctrl.HandleNodeForTest(ctx, node1)
	if got := ctrl.allocator.Get("node-1"); got != "10.0.0.0/24" {
		t.Errorf("node-1 re-handle: subnet = %s, want 10.0.0.0/24", got)
	}
}

func TestControllerLoadExisting(t *testing.T) {
	fakeServer, srv := newFakeDynamicServer(t)
	defer srv.Close()

	// Pre-populate the fake server with existing allocations
	fakeServer.status.Nodes["existing-node"] = api.NodeIPAMStatus{
		Subnet:  "10.0.5.0/24",
		Gateway: "10.0.5.1",
	}

	dynClient, err := dynamic.NewForConfig(fakeRESTConfig(srv.URL))
	if err != nil {
		t.Fatalf("creating dynamic client: %v", err)
	}

	ipamClient := api.NewClientFromDynamic(dynClient)
	kubeClient := fake2.NewSimpleClientset()

	ctrl, err := NewController(kubeClient, ipamClient, "10.0.0.0/16")
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}

	ctx := context.Background()
	if err := ctrl.loadExistingAllocations(ctx); err != nil {
		t.Fatalf("loadExistingAllocations: %v", err)
	}

	// Verify existing allocation was loaded
	if got := ctrl.allocator.Get("existing-node"); got != "10.0.5.0/24" {
		t.Errorf("existing-node subnet = %s, want 10.0.5.0/24", got)
	}

	// New node allocation should not collide
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "new-node"}}
	ctrl.HandleNodeForTest(ctx, node)

	newSubnet := ctrl.allocator.Get("new-node")
	if newSubnet == "10.0.5.0/24" {
		t.Error("new-node got same subnet as existing-node")
	}
	if newSubnet == "" {
		t.Error("new-node got no subnet")
	}
}

func TestControllerPatchFormat(t *testing.T) {
	fakeServer, srv := newFakeDynamicServer(t)
	defer srv.Close()

	dynClient, err := dynamic.NewForConfig(fakeRESTConfig(srv.URL))
	if err != nil {
		t.Fatalf("creating dynamic client: %v", err)
	}

	ipamClient := api.NewClientFromDynamic(dynClient)
	kubeClient := fake2.NewSimpleClientset()

	ctrl, err := NewController(kubeClient, ipamClient, "10.0.0.0/16")
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}

	ctx := context.Background()
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "patch-test-node"}}
	ctrl.HandleNodeForTest(ctx, node)

	if len(fakeServer.patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(fakeServer.patches))
	}

	patch := fakeServer.patches[0]
	statusData, ok := patch["status"].(map[string]interface{})
	if !ok {
		t.Fatal("patch missing status")
	}
	nodesData, ok := statusData["nodes"].(map[string]interface{})
	if !ok {
		t.Fatal("patch missing status.nodes")
	}
	nodeData, ok := nodesData["patch-test-node"].(map[string]interface{})
	if !ok {
		t.Fatal("patch missing status.nodes.patch-test-node")
	}

	subnet, ok := nodeData["subnet"].(string)
	if !ok || !strings.HasSuffix(subnet, "/24") {
		t.Errorf("patch subnet = %v, want /24 CIDR", nodeData["subnet"])
	}

	gateway, ok := nodeData["gateway"].(string)
	if !ok || gateway == "" {
		t.Fatal("patch missing gateway")
	}
	if !strings.HasSuffix(gateway, ".1") {
		t.Errorf("gateway = %s, want .1 address", gateway)
	}

	capacity, ok := nodeData["capacity"].(float64)
	if !ok || int(capacity) != 253 {
		t.Errorf("capacity = %v, want 253", nodeData["capacity"])
	}
}

func fakeRESTConfig(url string) *rest.Config {
	return &rest.Config{
		Host: url,
		ContentConfig: rest.ContentConfig{
			NegotiatedSerializer: runtime.NewSimpleNegotiatedSerializer(runtime.SerializerInfo{}),
		},
	}
}
