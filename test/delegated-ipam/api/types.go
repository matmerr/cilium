// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// CRDName is the fixed singleton name for the CiliumTestIPAM resource.
	CRDName = "default"

	// GroupName is the API group for test CRDs.
	GroupName = "test.cilium.io"

	// Version is the API version.
	Version = "v1alpha1"

	// ResourceName is the plural resource name.
	ResourceName = "ciliumtestipams"

	// SocketPath is the Unix socket used for CNI↔DaemonSet communication.
	SocketPath = "/var/run/cilium/test-ipam.sock"
)

var (
	// SchemeGroupVersion is the GroupVersion for CiliumTestIPAM.
	SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: Version}

	// SchemeBuilder is used to add types to the scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme

	// Resource returns a GroupResource for the given resource.
	Resource = func(resource string) schema.GroupResource {
		return SchemeGroupVersion.WithResource(resource).GroupResource()
	}
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&CiliumTestIPAM{},
		&CiliumTestIPAMList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// CiliumTestIPAM is a cluster-scoped CRD that tracks subnet allocations
// for delegated IPAM testing.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +genclient:nonNamespaced
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
type CiliumTestIPAM struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   CiliumTestIPAMSpec   `json:"spec"`
	Status CiliumTestIPAMStatus `json:"status,omitempty"`
}

// CiliumTestIPAMSpec defines the desired state.
type CiliumTestIPAMSpec struct {
	// Subnet is the overall IPv4 CIDR from which per-node /24s are carved.
	Subnet string `json:"subnet"`

	// IPv6Subnet is reserved for future IPv6 support.
	IPv6Subnet string `json:"ipv6Subnet,omitempty"`
}

// CiliumTestIPAMStatus holds per-node allocation state.
type CiliumTestIPAMStatus struct {
	// Nodes maps node names to their allocated subnet info.
	Nodes map[string]NodeIPAMStatus `json:"nodes,omitempty"`
}

// NodeIPAMStatus describes a single node's subnet allocation.
type NodeIPAMStatus struct {
	// Subnet is the /24 CIDR assigned to this node.
	Subnet string `json:"subnet"`

	// Gateway is the .1 address used as the default gateway.
	Gateway string `json:"gateway,omitempty"`

	// Capacity is the total usable IPs in this node's subnet (253 for a /24).
	Capacity int `json:"capacity,omitempty"`
}

// CiliumTestIPAMList is a list of CiliumTestIPAM resources.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CiliumTestIPAMList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CiliumTestIPAM `json:"items"`
}

// --- Hand-written DeepCopy methods (no code-gen) ---

func (in *CiliumTestIPAM) DeepCopyInto(out *CiliumTestIPAM) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *CiliumTestIPAM) DeepCopy() *CiliumTestIPAM {
	if in == nil {
		return nil
	}
	out := new(CiliumTestIPAM)
	in.DeepCopyInto(out)
	return out
}

func (in *CiliumTestIPAM) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

func (in *CiliumTestIPAMSpec) DeepCopyInto(out *CiliumTestIPAMSpec) {
	*out = *in
}

func (in *CiliumTestIPAMStatus) DeepCopyInto(out *CiliumTestIPAMStatus) {
	*out = *in
	if in.Nodes != nil {
		out.Nodes = make(map[string]NodeIPAMStatus, len(in.Nodes))
		for k, v := range in.Nodes {
			out.Nodes[k] = *v.DeepCopy()
		}
	}
}

func (in *NodeIPAMStatus) DeepCopyInto(out *NodeIPAMStatus) {
	*out = *in
}

func (in *NodeIPAMStatus) DeepCopy() *NodeIPAMStatus {
	if in == nil {
		return nil
	}
	out := new(NodeIPAMStatus)
	in.DeepCopyInto(out)
	return out
}

func (in *CiliumTestIPAMList) DeepCopyInto(out *CiliumTestIPAMList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]CiliumTestIPAM, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *CiliumTestIPAMList) DeepCopy() *CiliumTestIPAMList {
	if in == nil {
		return nil
	}
	out := new(CiliumTestIPAMList)
	in.DeepCopyInto(out)
	return out
}

func (in *CiliumTestIPAMList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}
