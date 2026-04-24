// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package daemonset

import (
	"testing"
)

func TestIPAllocatorBasic(t *testing.T) {
	a, err := NewIPAllocator("10.0.0.0/24")
	if err != nil {
		t.Fatalf("NewIPAllocator: %v", err)
	}

	// First allocation should be in the usable range (.2-.254)
	ip1, err := a.Allocate("container-1")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip1.String() == "10.0.0.0" || ip1.String() == "10.0.0.1" || ip1.String() == "10.0.0.255" {
		t.Errorf("got reserved IP %s", ip1)
	}

	// Second allocation should be different
	ip2, err := a.Allocate("container-2")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip1.Equal(ip2) {
		t.Errorf("two containers got the same IP: %s", ip1)
	}

	// Idempotent
	ip1Again, err := a.Allocate("container-1")
	if err != nil {
		t.Fatalf("re-Allocate: %v", err)
	}
	if !ip1.Equal(ip1Again) {
		t.Errorf("idempotent failed: %s != %s", ip1, ip1Again)
	}
}

func TestIPAllocatorRelease(t *testing.T) {
	a, err := NewIPAllocator("10.0.0.0/24")
	if err != nil {
		t.Fatalf("NewIPAllocator: %v", err)
	}

	ip1, _ := a.Allocate("c1")
	if ip1 == nil {
		t.Fatal("Allocate returned nil")
	}

	if !a.Release("c1") {
		t.Error("Release should return true for existing allocation")
	}
	if a.Release("c1") {
		t.Error("Release should return false for missing allocation")
	}

	// After release, the IP should be available again
	if a.Has("c1") {
		t.Error("Has should return false after release")
	}
}

func TestIPAllocatorHas(t *testing.T) {
	a, _ := NewIPAllocator("10.0.0.0/24")
	a.Allocate("c1")

	if !a.Has("c1") {
		t.Error("Has should return true for allocated container")
	}
	if a.Has("c2") {
		t.Error("Has should return false for unallocated container")
	}
}

func TestIPAllocatorGet(t *testing.T) {
	a, _ := NewIPAllocator("10.0.0.0/24")
	ip, _ := a.Allocate("c1")

	got := a.Get("c1")
	if got == nil || !got.Equal(ip) {
		t.Errorf("Get(c1) = %v, want %v", got, ip)
	}
	if a.Get("c2") != nil {
		t.Error("Get(c2) should be nil")
	}
}

func TestIPAllocatorGateway(t *testing.T) {
	a, _ := NewIPAllocator("10.0.0.0/24")
	gw := a.Gateway()
	if gw.String() != "10.0.0.1" {
		t.Errorf("Gateway() = %s, want 10.0.0.1", gw)
	}
}

func TestIPAllocatorAvailable(t *testing.T) {
	a, _ := NewIPAllocator("10.0.0.0/24")
	if a.Available() != 253 {
		t.Errorf("Available() = %d, want 253", a.Available())
	}
	a.Allocate("c1")
	if a.Available() != 252 {
		t.Errorf("Available() = %d, want 252", a.Available())
	}
}

func TestIPAllocatorExhaustion(t *testing.T) {
	a, _ := NewIPAllocator("10.0.0.0/24")

	// Allocate all 253 usable IPs
	for i := 0; i < 253; i++ {
		_, err := a.Allocate(string(rune(i)))
		if err != nil {
			t.Fatalf("Allocate %d: %v", i, err)
		}
	}

	if a.Available() != 0 {
		t.Errorf("Available() = %d, want 0", a.Available())
	}

	_, err := a.Allocate("overflow")
	if err == nil {
		t.Error("expected error on exhausted pool")
	}
}

func TestIPAllocatorInvalidSubnet(t *testing.T) {
	_, err := NewIPAllocator("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestIPAllocatorAnyCIDR(t *testing.T) {
	// Range supports any CIDR, not just /24
	a, err := NewIPAllocator("10.0.0.0/16")
	if err != nil {
		t.Fatalf("NewIPAllocator with /16: %v", err)
	}
	ip, err := a.Allocate("c1")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip == nil {
		t.Error("expected non-nil IP")
	}
}
