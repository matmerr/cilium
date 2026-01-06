#!/bin/bash
set -e

echo "===================================="
echo "Disable Cilium Gateway API"
echo "===================================="
echo
echo "This script removes Gateway API configuration from Cilium"
echo "when Cilium was installed via raw YAML manifests (not Helm)."
echo
echo "WARNING: This will:"
echo "  - Remove Gateway API configuration from cilium-config"
echo "  - Delete the cilium-secrets namespace and all secrets within"
echo "  - Remove all Gateway API RBAC resources"
echo "  - Restart Cilium operator and agent pods"
echo
read -p "Are you sure you want to continue? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi
echo

echo "Step 1: Checking if Cilium ConfigMap exists..."
if ! kubectl get configmap cilium-config -n kube-system &>/dev/null; then
    echo "ERROR: cilium-config ConfigMap not found in kube-system namespace"
    exit 1
fi
echo "✓ Cilium ConfigMap found"
echo

echo "Step 2: Removing Gateway API settings from Cilium ConfigMap..."
kubectl patch configmap cilium-config -n kube-system --type json -p='[
  {"op": "remove", "path": "/data/enable-gateway-api"},
  {"op": "remove", "path": "/data/enable-gateway-api-secrets-sync"},
  {"op": "remove", "path": "/data/enable-gateway-api-proxy-protocol"},
  {"op": "remove", "path": "/data/enable-gateway-api-app-protocol"},
  {"op": "remove", "path": "/data/enable-gateway-api-alpn"},
  {"op": "remove", "path": "/data/gateway-api-xff-num-trusted-hops"},
  {"op": "remove", "path": "/data/gateway-api-service-externaltrafficpolicy"},
  {"op": "remove", "path": "/data/gateway-api-secrets-namespace"},
  {"op": "remove", "path": "/data/gateway-api-hostnetwork-enabled"},
  {"op": "remove", "path": "/data/gateway-api-hostnetwork-nodelabelselector"}
]' 2>/dev/null || echo "⚠ Some Gateway API settings may not exist (this is OK)"

# Optionally disable envoy-config and l7-proxy if they were only enabled for Gateway API
read -p "Disable enable-envoy-config? (yes/no) [no]: " DISABLE_ENVOY
if [[ "$DISABLE_ENVOY" == "yes" ]]; then
    kubectl patch configmap cilium-config -n kube-system --type merge -p '{"data":{"enable-envoy-config":"false"}}'
    echo "✓ enable-envoy-config disabled"
fi

read -p "Disable enable-l7-proxy? (yes/no) [no]: " DISABLE_L7
if [[ "$DISABLE_L7" == "yes" ]]; then
    kubectl patch configmap cilium-config -n kube-system --type merge -p '{"data":{"enable-l7-proxy":"false"}}'
    echo "✓ enable-l7-proxy disabled"
fi

read -p "Disable enable-node-port? (yes/no) [no]: " DISABLE_NODEPORT
if [[ "$DISABLE_NODEPORT" == "yes" ]]; then
    kubectl patch configmap cilium-config -n kube-system --type merge -p '{"data":{"enable-node-port":"false"}}'
    echo "✓ enable-node-port disabled"
fi

echo "✓ ConfigMap patched"
echo

echo "Step 3: Removing GatewayClass (if exists)..."
if kubectl get gatewayclass cilium &>/dev/null; then
    kubectl delete gatewayclass cilium
    echo "✓ GatewayClass 'cilium' deleted"
else
    echo "✓ GatewayClass not found (already removed)"
fi
echo

echo "Step 4: Removing Gateway API ClusterRole and ClusterRoleBinding..."
kubectl delete clusterrole cilium-operator-gateway-api --ignore-not-found=true
kubectl delete clusterrolebinding cilium-operator-gateway-api --ignore-not-found=true
echo "✓ Gateway API ClusterRole and ClusterRoleBinding removed"
echo

echo "Step 5: Removing operator RBAC for secrets sync..."
kubectl delete role cilium-operator-gateway-secrets -n cilium-secrets --ignore-not-found=true
kubectl delete rolebinding cilium-operator-gateway-secrets -n cilium-secrets --ignore-not-found=true
echo "✓ Operator RBAC removed"
echo

echo "Step 6: Removing agent RBAC for secrets access..."
kubectl delete role cilium-gateway-secrets -n cilium-secrets --ignore-not-found=true
kubectl delete rolebinding cilium-gateway-secrets -n cilium-secrets --ignore-not-found=true
echo "✓ Agent RBAC removed"
echo

echo "Step 7: Removing cilium-secrets namespace..."
read -p "Delete cilium-secrets namespace and all contents? (yes/no) [yes]: " DELETE_NS
DELETE_NS=${DELETE_NS:-yes}
if [[ "$DELETE_NS" == "yes" ]]; then
    kubectl delete namespace cilium-secrets --ignore-not-found=true
    echo "✓ cilium-secrets namespace deleted"
else
    echo "⚠ Skipping namespace deletion (RBAC resources may remain)"
fi
echo

echo "Step 8: Restarting Cilium operator..."
kubectl rollout restart deployment/cilium-operator -n kube-system
echo "✓ Cilium operator restart initiated"
echo

echo "Step 9: Waiting for Cilium operator to be ready..."
kubectl rollout status deployment/cilium-operator -n kube-system --timeout=120s
echo "✓ Cilium operator is ready"
echo

echo "Step 10: Restarting Cilium agent pods..."
kubectl delete pods -n kube-system -l k8s-app=cilium
echo "✓ Cilium agent pods restart initiated"
echo

echo "Step 11: Waiting for Cilium agent pods to be ready..."
kubectl wait --for=condition=ready pod -n kube-system -l k8s-app=cilium --timeout=180s
echo "✓ Cilium agent pods are ready"
echo

echo "===================================="
echo "Gateway API Disabled Successfully!"
echo "===================================="
echo
echo "Configuration removed:"
echo "  - Gateway API settings from cilium-config ConfigMap"
echo "  - GatewayClass resource 'cilium'"
echo "  - ClusterRole: cilium-operator-gateway-api"
echo "  - ClusterRoleBinding: cilium-operator-gateway-api"
echo "  - Role: cilium-gateway-secrets (agent)"
echo "  - Role: cilium-operator-gateway-secrets (operator)"
if [[ "$DELETE_NS" == "yes" ]]; then
echo "  - Namespace: cilium-secrets"
fi
echo
echo "Cilium components have been restarted and are running."
echo
