#!/bin/bash
set -e

echo "===================================="
echo "Enable Cilium Gateway API"
echo "===================================="
echo
echo "This script patches the Cilium ConfigMap to enable Gateway API"
echo "when Cilium was installed via raw YAML manifests (not Helm)."
echo

# Configuration values based on Helm chart defaults
GATEWAY_API_ENABLED="true"
ENABLE_ENVOY_CONFIG="true"
ENABLE_L7_PROXY="true"
ENABLE_NODE_PORT="true"
GATEWAY_API_SECRETS_SYNC="true"
GATEWAY_API_PROXY_PROTOCOL="false"
GATEWAY_API_APP_PROTOCOL="false"
GATEWAY_API_ALPN="false"
GATEWAY_API_XFF_TRUSTED_HOPS="0"
GATEWAY_API_EXTERNAL_TRAFFIC_POLICY="Cluster"
GATEWAY_API_SECRETS_NAMESPACE="cilium-secrets"
GATEWAY_API_HOSTNETWORK_ENABLED="true"
GATEWAY_API_HOSTNETWORK_NODELABELSELECTOR=""

echo "Step 1: Checking if Cilium ConfigMap exists..."
if ! kubectl get configmap cilium-config -n kube-system &>/dev/null; then
    echo "ERROR: cilium-config ConfigMap not found in kube-system namespace"
    exit 1
fi
echo "✓ Cilium ConfigMap found"
echo

echo "Step 2: Patching Cilium ConfigMap with Gateway API settings..."
cat <<EOF | kubectl patch configmap cilium-config -n kube-system --patch-file=/dev/stdin
data:
  enable-gateway-api: "${GATEWAY_API_ENABLED}"
  enable-envoy-config: "${ENABLE_ENVOY_CONFIG}"
  enable-l7-proxy: "${ENABLE_L7_PROXY}"
  enable-node-port: "${ENABLE_NODE_PORT}"
  enable-gateway-api-secrets-sync: "${GATEWAY_API_SECRETS_SYNC}"
  enable-gateway-api-proxy-protocol: "${GATEWAY_API_PROXY_PROTOCOL}"
  enable-gateway-api-app-protocol: "${GATEWAY_API_APP_PROTOCOL}"
  enable-gateway-api-alpn: "${GATEWAY_API_ALPN}"
  gateway-api-xff-num-trusted-hops: "${GATEWAY_API_XFF_TRUSTED_HOPS}"
  gateway-api-service-externaltrafficpolicy: "${GATEWAY_API_EXTERNAL_TRAFFIC_POLICY}"
  gateway-api-secrets-namespace: "${GATEWAY_API_SECRETS_NAMESPACE}"
  gateway-api-hostnetwork-enabled: "${GATEWAY_API_HOSTNETWORK_ENABLED}"
  gateway-api-hostnetwork-nodelabelselector: "${GATEWAY_API_HOSTNETWORK_NODELABELSELECTOR}"
EOF
echo "✓ ConfigMap patched"
echo

echo "Step 3: Creating Gateway API secrets namespace..."
kubectl create namespace ${GATEWAY_API_SECRETS_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
echo "✓ Secrets namespace created/verified"
echo

echo "Step 4: Creating RBAC for Cilium agent (secrets read access)..."
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cilium-gateway-secrets
  namespace: ${GATEWAY_API_SECRETS_NAMESPACE}
  labels:
    app.kubernetes.io/part-of: cilium
rules:
- apiGroups: [""]
  resources: [secrets]
  verbs: [get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cilium-gateway-secrets
  namespace: ${GATEWAY_API_SECRETS_NAMESPACE}
  labels:
    app.kubernetes.io/part-of: cilium
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cilium-gateway-secrets
subjects:
- kind: ServiceAccount
  name: cilium
  namespace: kube-system
EOF
echo "✓ Agent RBAC created"
echo

echo "Step 5: Creating RBAC for Cilium operator (secrets sync)..."
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cilium-operator-gateway-secrets
  namespace: ${GATEWAY_API_SECRETS_NAMESPACE}
  labels:
    app.kubernetes.io/part-of: cilium
rules:
- apiGroups: [""]
  resources: [secrets]
  verbs: [create, delete, update, patch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cilium-operator-gateway-secrets
  namespace: ${GATEWAY_API_SECRETS_NAMESPACE}
  labels:
    app.kubernetes.io/part-of: cilium
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cilium-operator-gateway-secrets
subjects:
- kind: ServiceAccount
  name: cilium-operator
  namespace: kube-system
EOF
echo "✓ Operator RBAC created"
echo

echo "Step 6: Adding Gateway API permissions to cilium-operator..."
# For manual installations, we create an additional ClusterRole and bind it
# This is safer than modifying the existing cilium-operator ClusterRole
# Helm modifies the existing ClusterRole, but we use an additive approach

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cilium-operator-gateway-api
  labels:
    app.kubernetes.io/part-of: cilium
    app.kubernetes.io/component: operator
rules:
# Gateway API resources - read access
- apiGroups:
  - gateway.networking.k8s.io
  resources:
  - gatewayclasses
  - gateways
  - tlsroutes
  - httproutes
  - grpcroutes
  - referencegrants
  - referencepolicies
  verbs:
  - get
  - list
  - watch
# Gateway API resources - patch GatewayClass
- apiGroups:
  - gateway.networking.k8s.io
  resources:
  - gatewayclasses
  verbs:
  - patch
# Gateway API resources - status updates
- apiGroups:
  - gateway.networking.k8s.io
  resources:
  - gatewayclasses/status
  - gateways/status
  - httproutes/status
  - grpcroutes/status
  - tlsroutes/status
  verbs:
  - update
  - patch
# Cilium Gateway resources
- apiGroups:
  - cilium.io
  resources:
  - ciliumgatewayclassconfigs
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - cilium.io
  resources:
  - ciliumgatewayclassconfigs/status
  verbs:
  - update
  - patch
# Service/Endpoints management (for Gateway API)
- apiGroups:
  - ""
  resources:
  - services
  - endpoints
  verbs:
  - create
  - update
  - delete
  - patch
  - get
  - list
  - watch
# Secrets access (for Gateway API)
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - list
  - watch
# Multi-cluster service imports
- apiGroups:
  - multicluster.x-k8s.io
  resources:
  - serviceimports
  verbs:
  - get
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cilium-operator-gateway-api
  labels:
    app.kubernetes.io/part-of: cilium
    app.kubernetes.io/component: operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cilium-operator-gateway-api
subjects:
- kind: ServiceAccount
  name: cilium-operator
  namespace: kube-system
EOF

echo "✓ Gateway API ClusterRole and ClusterRoleBinding created"
echo

echo "Step 7: Restarting Cilium operator to pick up Gateway API changes..."
kubectl rollout restart deployment/cilium-operator -n kube-system
echo "✓ Cilium operator restart initiated"
echo

echo "Step 8: Waiting for Cilium operator to be ready..."
kubectl rollout status deployment/cilium-operator -n kube-system --timeout=120s
echo "✓ Cilium operator is ready"
echo

echo "Step 9: Restarting Cilium agent pods to pick up new configuration..."
kubectl delete pods -n kube-system -l k8s-app=cilium
echo "✓ Cilium agent pods restart initiated"
echo

echo "Step 10: Waiting for Cilium agent pods to be ready..."
kubectl wait --for=condition=ready pod -n kube-system -l k8s-app=cilium --timeout=180s
echo "✓ Cilium agent pods are ready"
echo

echo "Step 11: Creating default GatewayClass (optional)..."
if kubectl get crd gatewayclasses.gateway.networking.k8s.io &>/dev/null; then
    kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: cilium
spec:
  controllerName: io.cilium/gateway-controller
  description: The default Cilium GatewayClass
EOF
    echo "✓ GatewayClass 'cilium' created"
else
    echo "⚠ Skipping GatewayClass creation - CRDs not installed yet"
    echo "  Run: kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml"
fi
echo

echo "===================================="
echo "Gateway API Enabled Successfully!"
echo "===================================="
echo
echo "Configuration applied:"
echo "  - enable-gateway-api: ${GATEWAY_API_ENABLED}"
echo "  - enable-envoy-config: ${ENABLE_ENVOY_CONFIG}"
echo "  - enable-l7-proxy: ${ENABLE_L7_PROXY}"
echo "  - enable-node-port: ${ENABLE_NODE_PORT}"
echo "  - gateway-api-secrets-namespace: ${GATEWAY_API_SECRETS_NAMESPACE}"
echo
echo "RBAC created:"
echo "  - Role: cilium-gateway-secrets (agent read access)"
echo "  - Role: cilium-operator-gateway-secrets (operator sync access)"
echo "  - ClusterRole: cilium-operator-gateway-api (Gateway API permissions)"
echo "  - ClusterRoleBinding: cilium-operator-gateway-api"
echo
echo "Note: This script creates an additional ClusterRole for Gateway API permissions."
echo "      Helm installations modify the existing cilium-operator ClusterRole directly."
echo "      Both approaches provide the same functional result."
echo
echo "Next steps:"
echo "  1. Install Gateway API CRDs (if not already installed):"
echo "     kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml"
echo
echo "  2. Apply your Gateway resources:"
echo "     kubectl apply -f 01-gatewayclass.yaml"
echo "     kubectl apply -f 02-gateway.yaml"
echo "     kubectl apply -f 03-echo-app.yaml"
echo "     kubectl apply -f 04-httproute.yaml"
echo
