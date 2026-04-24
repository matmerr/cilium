// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"testing"
)

func TestSubnetAllocatorBasic(t *testing.T) {
	a, err := NewSubnetAllocator("10.0.0.0/16")
	if err != nil {
		t.Fatalf("NewSubnetAllocator: %v", err)
	}

	// First allocation should get 10.0.0.0/24
	cidr, err := a.Allocate("node-1")
	if err != nil {
		t.Fatalf("Allocate node-1: %v", err)
	}
	if cidr != "10.0.0.0/24" {
		t.Errorf("expected 10.0.0.0/24, got %s", cidr)
	}

	// Second allocation should get 10.0.1.0/24
	cidr, err = a.Allocate("node-2")
	if err != nil {
		t.Fatalf("Allocate node-2: %v", err)
	}
	if cidr != "10.0.1.0/24" {
		t.Errorf("expected 10.0.1.0/24, got %s", cidr)
	}

	// Idempotent: same node returns same allocation
	cidr2, err := a.Allocate("node-1")
	if err != nil {
		t.Fatalf("re-Allocate node-1: %v", err)
	}
	if cidr2 != "10.0.0.0/24" {
		t.Errorf("idempotent check: expected 10.0.0.0/24, got %s", cidr2)
	}

	// Get
	if got := a.Get("node-1"); got != "10.0.0.0/24" {
		t.Errorf("Get node-1: expected 10.0.0.0/24, got %s", got)
	}
	if got := a.Get("node-3"); got != "" {
		t.Errorf("Get node-3: expected empty, got %s", got)
	}
}

func TestSubnetAllocatorRelease(t *testing.T) {
	a, err := NewSubnetAllocator("10.0.0.0/24")
	if err != nil {
		t.Fatalf("NewSubnetAllocator: %v", err)
	}

	// /24 parent can only have 1 /24 subnet
	cidr, err := a.Allocate("node-1")
	if err != nil {
		t.Fatalf("Allocate node-1: %v", err)
	}
	if cidr != "10.0.0.0/24" {
		t.Errorf("expected 10.0.0.0/24, got %s", cidr)
	}

	// Should be full now
	_, err = a.Allocate("node-2")
	if err == nil {
		t.Error("expected error allocating from exhausted pool")
	}

	// Release and try again
	a.Release("node-1")
	cidr, err = a.Allocate("node-2")
	if err != nil {
		t.Fatalf("Allocate after release: %v", err)
	}
	if cidr != "10.0.0.0/24" {
		t.Errorf("expected 10.0.0.0/24 after release, got %s", cidr)
	}
}

func TestSubnetAllocatorExhaustion(t *testing.T) {
	// /30 = only 4 IPs = 0 /24 subnets possible
	_, err := NewSubnetAllocator("10.0.0.0/30")
	if err == nil {
		t.Error("expected error for /30 parent")
	}
}

func TestSubnetAllocatorLoadExisting(t *testing.T) {
	a, err := NewSubnetAllocator("10.0.0.0/16")
	if err != nil {
		t.Fatalf("NewSubnetAllocator: %v", err)
	}

	// Load a pre-existing allocation
	if err := a.LoadExisting("node-5", "10.0.5.0/24"); err != nil {
		t.Fatalf("LoadExisting: %v", err)
	}

	// Should return the loaded allocation
	if got := a.Get("node-5"); got != "10.0.5.0/24" {
		t.Errorf("expected 10.0.5.0/24, got %s", got)
	}

	// New allocation should skip the loaded offset
	for i := 0; i < 5; i++ {
		name := "node-" + string(rune('a'+i))
		_, err := a.Allocate(name)
		if err != nil {
			t.Fatalf("Allocate %s: %v", name, err)
		}
	}
	// Offset 5 should be skipped (belongs to node-5)
	cidr, err := a.Allocate("node-f")
	if err != nil {
		t.Fatalf("Allocate node-f: %v", err)
	}
	if cidr == "10.0.5.0/24" {
		t.Error("allocated already-loaded subnet 10.0.5.0/24")
	}
}

func TestSubnetAllocatorInvalidParent(t *testing.T) {
	_, err := NewSubnetAllocator("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestGatewayIP(t *testing.T) {
	tests := []struct {
		subnet string
		want   string
	}{
		{"10.0.0.0/24", "10.0.0.1"},
		{"10.0.1.0/24", "10.0.1.1"},
		{"192.168.0.0/24", "192.168.0.1"},
	}
	for _, tt := range tests {
		got, err := GatewayIP(tt.subnet)
		if err != nil {
			t.Errorf("GatewayIP(%s): %v", tt.subnet, err)
			continue
		}
		if got != tt.want {
			t.Errorf("GatewayIP(%s) = %s, want %s", tt.subnet, got, tt.want)
		}
	}
}
