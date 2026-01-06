# Cilium Gateway API: Complete Helm Chart Changes Analysis

This document provides a comprehensive analysis of all changes that occur when enabling Gateway API in Cilium via Helm chart (`gatewayAPI.enabled=true`).

## Table of Contents

- [Quick Summary](#quick-summary)
- [Prerequisites](#prerequisites)
- [Helm Values Configuration](#helm-values-configuration)
- [ConfigMap Changes](#configmap-changes)
- [Namespace Creation](#namespace-creation)
- [RBAC Changes](#rbac-changes)
- [GatewayClass Resource](#gatewayclass-resource)
- [Validation Rules](#validation-rules)
- [Complete Resource List](#complete-resource-list)
- [Manual Configuration Guide](#manual-configuration-guide)

---

## Quick Summary

When you set `gatewayAPI.enabled=true` in Helm, the following happens:

1. **ConfigMap** (`cilium-config`): 13 new Gateway API configuration keys added
2. **Namespace**: Creates `cilium-secrets` namespace (configurable)
3. **RBAC**: Creates 2 Roles and 2 RoleBindings for secrets access
4. **ClusterRole**: Adds Gateway API resource permissions to `cilium-operator`
5. **GatewayClass**: Optionally creates a `GatewayClass` resource named "cilium"
6. **Validation**: Enforces prerequisites (l7Proxy, kubeProxyReplacement settings)

---

## Prerequisites

### Required Settings

Gateway API has strict prerequisites that are automatically validated by the Helm chart:

#### 1. L7 Proxy Must Be Enabled

```yaml
l7Proxy: true # REQUIRED - Default is true
```

**Validation Rule:**

```go
// From templates/validate.yaml
if gatewayAPI.enabled:
  if not l7Proxy:
    FAIL: "Gateway API requires .Values.l7Proxy to be set to 'true'"
```

#### 2. NodePort OR Kube-Proxy Replacement Required

You must enable **one** of the following:

**Option A: Enable NodePort** (Simpler)

```yaml
nodePort:
  enabled: true
```

**Option B: Enable Kube-Proxy Replacement**

```yaml
kubeProxyReplacement: "true" # or "probe", "strict"
```

**Validation Rule:**

```go
// From templates/validate.yaml
if gatewayAPI.enabled:
  if kubeProxyReplacement == "disabled":
    FAIL: "Gateway API requires kubeProxyReplacement to be 'false' or 'true'"
  if kubeProxyReplacement not set and upgradeCompatibility < 1.14:
    FAIL: "Must explicitly set kubeProxyReplacement"
```

**Why is this required?**

- Gateway API creates LoadBalancer services that need NodePort allocation
- Cilium's Gateway implementation relies on NodePort or kube-proxy replacement for service traffic routing
- Without either option, Gateway services cannot receive traffic

#### 3. External Traffic Policy

```yaml
gatewayAPI:
  externalTrafficPolicy: "Cluster" # or "Local"
```

**Validation Rule:**

```go
if gatewayAPI.enabled:
  if externalTrafficPolicy not in ["Cluster", "Local"]:
    FAIL: "externalTrafficPolicy must be 'Cluster' or 'Local'"
```

---

## Helm Values Configuration

### Default Values

```yaml
# From install/kubernetes/cilium/values.yaml

gatewayAPI:
  # Master switch - enables Gateway API controller in cilium-operator
  enabled: false

  # Enable PROXY protocol for all Gateway listeners
  # WARNING: Once enabled, ONLY Proxy protocol traffic accepted
  enableProxyProtocol: false

  # Enable Backend Protocol selection (GEP-1911)
  # Allows services to specify protocol via appProtocol field
  enableAppProtocol: false

  # Enable ALPN negotiation (HTTP/2, then HTTP/1.1)
  # Also enables appProtocol support
  enableAlpn: false

  # X-Forwarded-For header: number of trusted proxy hops
  # Used for determining origin client IP
  xffNumTrustedHops: 0

  # Traffic routing policy for Gateway LoadBalancer services
  # "Cluster" = traffic routed to any backend across cluster
  # "Local" = traffic only to backends on same node (preserves source IP)
  # Ignored when hostNetwork.enabled=true
  externalTrafficPolicy: "Cluster"

  # GatewayClass resource creation
  gatewayClass:
    # "auto" = create only if GatewayClass CRD exists
    # "true" = always create (will fail if CRD missing)
    # "false" = never create
    create: auto

  # TLS secrets namespace configuration
  secretsNamespace:
    # Create the namespace
    create: true

    # Namespace name where Envoy retrieves TLS secrets
    name: cilium-secrets

    # Auto-sync TLS secrets from Gateway namespaces to secrets namespace
    # If false, secrets must be manually copied to cilium-secrets
    sync: true

  # Host network configuration
  hostNetwork:
    # Expose Gateway listeners on host network
    # Use for bare-metal without LoadBalancer
    enabled: false

    # Node selector for host network gateways
    nodes:
      matchLabels: {}
      # Example:
      # matchLabels:
      #   kubernetes.io/os: linux
      #   kubernetes.io/hostname: kind-worker

# NodePort configuration (REQUIRED for Gateway API)
nodePort:
  # Must be true for Gateway API (unless using kubeProxyReplacement)
  enabled: false

  # Port range for NodePort services (default: 30000-32767)
  # range: "30000,32767"

  # Bind protection - prevent apps from binding to service ports
  bindProtection: true

  # Auto-protect NodePort range from ephemeral port conflicts
  autoProtectPortRange: true

  # Enable health check for NodePort services
  enableHealthCheck: true

# Kube-Proxy Replacement (ALTERNATIVE to nodePort.enabled)
kubeProxyReplacement: "false"
# Options:
#   "true" - Full replacement (enables nodePort automatically)
#   "false" - No replacement (must enable nodePort.enabled)
#   "probe" - Auto-detect capabilities
#   "strict" - Strict mode with BPF NodePort
#   "disabled" - Explicitly disabled (FAILS with Gateway API)

# L7 Proxy (REQUIRED for Gateway API)
l7Proxy: true
```

### Minimal Gateway API Configuration

```yaml
# Minimal configuration to enable Gateway API
gatewayAPI:
  enabled: true

nodePort:
  enabled: true

l7Proxy: true
```

### Recommended Production Configuration

```yaml
gatewayAPI:
  enabled: true
  externalTrafficPolicy: "Local" # Preserve source IP
  enableAppProtocol: true # Backend protocol selection
  secretsNamespace:
    name: cilium-secrets
    sync: true # Auto-sync TLS secrets
  gatewayClass:
    create: auto # Create if CRDs present

nodePort:
  enabled: true
  bindProtection: true
  autoProtectPortRange: true
  enableHealthCheck: true

l7Proxy: true
```

---

## ConfigMap Changes

### File: `templates/cilium-configmap.yaml`

When `gatewayAPI.enabled=true`, the following keys are added to the `cilium-config` ConfigMap in the `kube-system` namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-config
  namespace: kube-system
data:
  # === Core Gateway API Settings ===

  # Master switch - enables Gateway API controller in operator
  enable-gateway-api: "true"

  # Auto-enabled with Gateway API (enables CiliumEnvoyConfig CRD)
  enable-envoy-config: "true"

  # Required for L7 HTTP routing
  enable-l7-proxy: "true"

  # Required for Gateway LoadBalancer services
  enable-node-port: "true"

  # === Gateway API Specific Settings ===

  # Auto-sync TLS secrets to secrets namespace
  # Value: "true" or "false"
  enable-gateway-api-secrets-sync: "true"

  # Enable PROXY protocol for all Gateway listeners
  # Value: "true" or "false"
  enable-gateway-api-proxy-protocol: "false"

  # Enable backend protocol selection (appProtocol field)
  # Value: "true" or "false"
  enable-gateway-api-app-protocol: "false"

  # Enable ALPN negotiation (HTTP/2, HTTP/1.1)
  # Value: "true" or "false"
  enable-gateway-api-alpn: "false"

  # X-Forwarded-For: number of trusted proxy hops
  # Value: integer as string (e.g., "0", "1", "2")
  gateway-api-xff-num-trusted-hops: "0"

  # External traffic policy for Gateway services
  # Value: "Cluster" or "Local"
  gateway-api-service-externaltrafficpolicy: "Cluster"

  # Namespace where TLS secrets are stored for Envoy
  # Value: namespace name
  gateway-api-secrets-namespace: "cilium-secrets"

  # Enable host network exposure for Gateways
  # Value: "true" or "false"
  gateway-api-hostnetwork-enabled: "false"

  # Node labels for host network gateway placement
  # Value: comma-separated key=value pairs or empty string
  gateway-api-hostnetwork-nodelabelselector: ""
```

### ConfigMap Logic

The Helm template conditionally sets `enable-envoy-config` when ANY of these are enabled:

```go
if .Values.envoyConfig.enabled OR
   .Values.ingressController.enabled OR
   .Values.gatewayAPI.enabled OR
   .Values.loadBalancer.l7.backend == "envoy":
    enable-envoy-config: "true"
```

---

## Namespace Creation

### File: `templates/cilium-secrets-namespace.yaml`

Creates a dedicated namespace for TLS secrets used by Gateway API.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cilium-secrets # Value from gatewayAPI.secretsNamespace.name
  labels:
    app.kubernetes.io/part-of: cilium
  annotations: {}
```

**Conditions:**

- Created when: `gatewayAPI.enabled=true` AND `gatewayAPI.secretsNamespace.create=true`
- Name configurable via: `gatewayAPI.secretsNamespace.name`
- Default name: `cilium-secrets`

**Purpose:**

- Central location for TLS certificates and secrets used by Envoy
- Isolates Gateway API secrets from application namespaces
- Enables secret syncing from Gateway namespaces

---

## RBAC Changes

Gateway API requires extensive RBAC permissions for both Cilium agents and operators.

### 1. Cilium Agent - Role in Secrets Namespace

**File:** `templates/cilium-agent/role.yaml`

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cilium-gateway-secrets
  namespace: cilium-secrets # gatewayAPI.secretsNamespace.name
  labels:
    app.kubernetes.io/part-of: cilium
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list, watch]
```

**Conditions:**

- Created when: `gatewayAPI.enabled=true` AND `gatewayAPI.secretsNamespace.name` is set
- Purpose: Allows Cilium agents to read TLS secrets for Envoy configuration

### 2. Cilium Agent - RoleBinding in Secrets Namespace

**File:** `templates/cilium-agent/rolebinding.yaml`

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cilium-gateway-secrets
  namespace: cilium-secrets
  labels:
    app.kubernetes.io/part-of: cilium
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cilium-gateway-secrets
subjects:
  - kind: ServiceAccount
    name: cilium # serviceAccounts.cilium.name
    namespace: kube-system
```

**Binds:** `cilium` ServiceAccount → `cilium-gateway-secrets` Role

### 3. Cilium Operator - Role in Secrets Namespace

**File:** `templates/cilium-operator/role.yaml`

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cilium-operator-gateway-secrets
  namespace: cilium-secrets
  labels:
    app.kubernetes.io/part-of: cilium
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [create, delete, update, patch]
```

**Conditions:**

- Created when: `gatewayAPI.enabled=true` AND `gatewayAPI.secretsNamespace.sync=true`
- Purpose: Allows operator to sync TLS secrets TO the secrets namespace

### 4. Cilium Operator - RoleBinding in Secrets Namespace

**File:** `templates/cilium-operator/rolebinding.yaml`

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cilium-operator-gateway-secrets
  namespace: cilium-secrets
  labels:
    app.kubernetes.io/part-of: cilium
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cilium-operator-gateway-secrets
subjects:
  - kind: ServiceAccount
    name: cilium-operator # serviceAccounts.operator.name
    namespace: kube-system
```

**Binds:** `cilium-operator` ServiceAccount → `cilium-operator-gateway-secrets` Role

### 5. Cilium Operator - ClusterRole Additions

**File:** `templates/cilium-operator/clusterrole.yaml`

The `cilium-operator` ClusterRole gains extensive new permissions:

#### Core Resource Permissions

```yaml
- apiGroups: [""]
  resources: [secrets]
  verbs: [get, list, watch] # Added when gatewayAPI.enabled=true

- apiGroups: [""]
  resources: [services, endpoints]
  verbs:
    - get, list, watch # Existing
    - create, update, delete, patch # ADDED for Gateway API
```

#### Gateway API Resources

```yaml
- apiGroups: [gateway.networking.k8s.io]
  resources:
    - gatewayclasses
    - gateways
    - httproutes
    - grpcroutes
    - tlsroutes
    - referencegrants
    - referencepolicies
  verbs: [get, list, watch]

- apiGroups: [gateway.networking.k8s.io]
  resources: [gatewayclasses]
  verbs: [patch]

- apiGroups: [gateway.networking.k8s.io]
  resources:
    - gatewayclasses/status
    - gateways/status
    - httproutes/status
    - grpcroutes/status
    - tlsroutes/status
  verbs: [update, patch]
```

#### Cilium Custom Resources

```yaml
- apiGroups: [cilium.io]
  resources: [ciliumgatewayclassconfigs]
  verbs: [get, list, watch]

- apiGroups: [cilium.io]
  resources: [ciliumgatewayclassconfigs/status]
  verbs: [update, patch]
```

#### Multi-Cluster Service API (Conditional)

```yaml
# Added when gatewayAPI.enabled OR clustermesh.enableMCSAPISupport
- apiGroups: [multicluster.x-k8s.io]
  resources: [serviceimports]
  verbs: [get, list, watch]
```

---

## GatewayClass Resource

### File: `templates/cilium-gateway-api-class.yaml`

Optionally creates a default `GatewayClass` resource.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: cilium
  labels: {} # From commonLabels
spec:
  controllerName: io.cilium/gateway-controller
  description: The default Cilium GatewayClass
```

**Creation Logic:**

```go
if gatewayAPI.enabled == true:
  if gatewayAPI.gatewayClass.create == "true":
    CREATE GATEWAYCLASS
  elif gatewayAPI.gatewayClass.create == "auto":
    if "gateway.networking.k8s.io/v1/GatewayClass" CRD exists:
      CREATE GATEWAYCLASS
    else:
      SKIP (prevents Helm failure if CRDs not installed)
  else:  # gatewayAPI.gatewayClass.create == "false"
    SKIP
```

**Default Setting:** `gatewayAPI.gatewayClass.create: auto`

**Controller Name:** `io.cilium/gateway-controller`

- This identifier tells Kubernetes that Cilium should reconcile Gateway resources
- Any Gateway with `gatewayClassName: cilium` will be managed by Cilium

---

## Validation Rules

### File: `templates/validate.yaml`

Helm enforces strict validation rules that will **FAIL installation** if not met:

### 1. L7 Proxy Requirement

```yaml
{{- if or .Values.ingressController.enabled .Values.gatewayAPI.enabled }}
  {{- if not .Values.l7Proxy }}
    {{ fail "Gateway API requires .Values.l7Proxy to be set to 'true'" }}
  {{- end }}
{{- end }}
```

**Error Message:**

```
Error: template validation error: Gateway API requires .Values.l7Proxy to be set to 'true'
```

### 2. External Traffic Policy Validation

```yaml
{{- if .Values.gatewayAPI.enabled }}
  {{- if not (or (eq .Values.gatewayAPI.externalTrafficPolicy "Cluster")
                  (eq .Values.gatewayAPI.externalTrafficPolicy "Local")) }}
    {{ fail "Cilium GatewayAPI needs an externalTrafficPolicy set to 'Cluster' or 'Local'." }}
  {{- end }}
{{- end }}
```

**Error Message:**

```
Error: template validation error: Cilium GatewayAPI needs an externalTrafficPolicy set to 'Cluster' or 'Local'.
```

### 3. Kube-Proxy Replacement Requirement

```yaml
{{- if or .Values.envoyConfig.enabled .Values.gatewayAPI.enabled }}
  {{- if eq (toString .Values.kubeProxyReplacement) "disabled" }}
    {{ fail "Gateway API requires kubeProxyReplacement to be 'false' or 'true'" }}
  {{- end }}
{{- end }}
```

**Error Message:**

```
Error: template validation error: Gateway API requires .Values.kubeProxyReplacement to be explicitly set to 'false' or 'true'
```

**Why this matters:**

- `kubeProxyReplacement: "disabled"` is NOT the same as `kubeProxyReplacement: "false"`
- Must be explicitly set to `"false"` or `"true"` (or probe/strict)
- If not set and `upgradeCompatibility < 1.14`, installation will fail

---

## Complete Resource List

Summary of all Kubernetes resources created/modified when `gatewayAPI.enabled=true`:

| Resource Type    | Name                              | Namespace        | Action       | Condition                       |
| ---------------- | --------------------------------- | ---------------- | ------------ | ------------------------------- |
| **ConfigMap**    | `cilium-config`                   | `kube-system`    | **MODIFIED** | Always                          |
| **Namespace**    | `cilium-secrets`                  | -                | **CREATED**  | `secretsNamespace.create=true`  |
| **Role**         | `cilium-gateway-secrets`          | `cilium-secrets` | **CREATED**  | `secretsNamespace.name` set     |
| **RoleBinding**  | `cilium-gateway-secrets`          | `cilium-secrets` | **CREATED**  | `secretsNamespace.name` set     |
| **Role**         | `cilium-operator-gateway-secrets` | `cilium-secrets` | **CREATED**  | `secretsNamespace.sync=true`    |
| **RoleBinding**  | `cilium-operator-gateway-secrets` | `cilium-secrets` | **CREATED**  | `secretsNamespace.sync=true`    |
| **ClusterRole**  | `cilium-operator`                 | -                | **MODIFIED** | Always                          |
| **GatewayClass** | `cilium`                          | -                | **CREATED**  | `gatewayClass.create=true/auto` |

### Impact Summary

**Total Resources Created:** 5-6 new resources
**Resources Modified:** 2 existing resources (ConfigMap, ClusterRole)
**Namespaces Affected:** 2 (`kube-system`, `cilium-secrets`)

---

## Manual Configuration Guide

If Cilium was installed via raw YAML (not Helm), use this guide to manually enable Gateway API.

### Step 1: Patch ConfigMap

```bash
kubectl patch configmap cilium-config -n kube-system --type merge --patch '
data:
  enable-gateway-api: "true"
  enable-envoy-config: "true"
  enable-l7-proxy: "true"
  enable-node-port: "true"
  enable-gateway-api-secrets-sync: "true"
  enable-gateway-api-proxy-protocol: "false"
  enable-gateway-api-app-protocol: "false"
  enable-gateway-api-alpn: "false"
  gateway-api-xff-num-trusted-hops: "0"
  gateway-api-service-externaltrafficpolicy: "Cluster"
  gateway-api-secrets-namespace: "cilium-secrets"
  gateway-api-hostnetwork-enabled: "false"
  gateway-api-hostnetwork-nodelabelselector: ""
'
```

### Step 2: Create Secrets Namespace

```bash
kubectl create namespace cilium-secrets
kubectl label namespace cilium-secrets app.kubernetes.io/part-of=cilium
```

### Step 3: Create Agent RBAC (Secrets Read Access)

```bash
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cilium-gateway-secrets
  namespace: cilium-secrets
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
  namespace: cilium-secrets
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
```

### Step 4: Create Operator RBAC (Secrets Sync)

```bash
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cilium-operator-gateway-secrets
  namespace: cilium-secrets
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
  namespace: cilium-secrets
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
```

### Step 5: Update Operator ClusterRole

```bash
# Add Gateway API permissions to cilium-operator ClusterRole
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cilium-operator-gateway-api-addon
  labels:
    app.kubernetes.io/part-of: cilium
rules:
# Gateway API resources
- apiGroups: [gateway.networking.k8s.io]
  resources:
    - gatewayclasses
    - gateways
    - httproutes
    - grpcroutes
    - tlsroutes
    - referencegrants
    - referencepolicies
  verbs: [get, list, watch]
- apiGroups: [gateway.networking.k8s.io]
  resources: [gatewayclasses]
  verbs: [patch]
- apiGroups: [gateway.networking.k8s.io]
  resources:
    - gatewayclasses/status
    - gateways/status
    - httproutes/status
    - grpcroutes/status
    - tlsroutes/status
  verbs: [update, patch]
# Cilium Gateway resources
- apiGroups: [cilium.io]
  resources: [ciliumgatewayclassconfigs]
  verbs: [get, list, watch]
- apiGroups: [cilium.io]
  resources: [ciliumgatewayclassconfigs/status]
  verbs: [update, patch]
# Service/Endpoints management
- apiGroups: [""]
  resources: [services, endpoints]
  verbs: [create, update, delete, patch]
# Secrets access
- apiGroups: [""]
  resources: [secrets]
  verbs: [get, list, watch]
EOF

# Bind the additional ClusterRole to cilium-operator
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cilium-operator-gateway-api-addon
  labels:
    app.kubernetes.io/part-of: cilium
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cilium-operator-gateway-api-addon
subjects:
- kind: ServiceAccount
  name: cilium-operator
  namespace: kube-system
EOF
```

### Step 6: Restart Cilium Components

```bash
# Restart operator to activate Gateway API controller
kubectl rollout restart deployment/cilium-operator -n kube-system
kubectl rollout status deployment/cilium-operator -n kube-system --timeout=120s

# Restart agents to pick up new ConfigMap
kubectl delete pods -n kube-system -l k8s-app=cilium
kubectl wait --for=condition=ready pod -n kube-system -l k8s-app=cilium --timeout=180s
```

### Step 7: Create GatewayClass (Optional)

```bash
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: cilium
spec:
  controllerName: io.cilium/gateway-controller
  description: The default Cilium GatewayClass
EOF
```

### Automated Script

For convenience, use the provided script:

```bash
./enable-gateway-api.sh
```

This script automates all the steps above.

---

## Verification

### Check ConfigMap Settings

```bash
kubectl get configmap cilium-config -n kube-system -o yaml | grep -E "gateway|envoy|l7-proxy|node-port"
```

Expected output:

```yaml
enable-gateway-api: "true"
enable-envoy-config: "true"
enable-l7-proxy: "true"
enable-node-port: "true"
enable-gateway-api-secrets-sync: "true"
gateway-api-secrets-namespace: "cilium-secrets"
# ... other gateway-api settings
```

### Check Operator Logs

```bash
kubectl logs -n kube-system -l name=cilium-operator --tail=50 | grep -i gateway
```

Look for:

```
level=info msg="Gateway API controller started"
level=info msg="Gateway API support enabled"
```

### Check RBAC

```bash
# Verify secrets namespace
kubectl get namespace cilium-secrets

# Verify Role/RoleBinding in secrets namespace
kubectl get role,rolebinding -n cilium-secrets

# Verify ClusterRole permissions
kubectl get clusterrole cilium-operator -o yaml | grep -A 10 gateway.networking
```

### Check GatewayClass

```bash
kubectl get gatewayclass cilium
```

Expected output:

```
NAME     CONTROLLER                      ACCEPTED   AGE
cilium   io.cilium/gateway-controller    True       1m
```

---

## Common Issues

### 1. Helm Install Fails: "l7Proxy must be true"

**Error:**

```
Error: template validation error: Gateway API requires .Values.l7Proxy to be set to 'true'
```

**Solution:**

```bash
helm upgrade cilium cilium/cilium --reuse-values --set l7Proxy=true
```

### 2. Helm Install Fails: "kubeProxyReplacement must be set"

**Error:**

```
Error: template validation error: Gateway API requires kubeProxyReplacement to be explicitly set
```

**Solution:**

```bash
# Option A: Enable kube-proxy replacement
helm upgrade cilium cilium/cilium --reuse-values \
  --set kubeProxyReplacement=true

# Option B: Keep kube-proxy, just set flag explicitly
helm upgrade cilium cilium/cilium --reuse-values \
  --set kubeProxyReplacement=false \
  --set nodePort.enabled=true
```

### 3. Gateway Stuck in PROGRAMMED=False

**Cause:** NodePort not enabled

**Check:**

```bash
kubectl get configmap cilium-config -n kube-system -o yaml | grep enable-node-port
```

**Solution:**

```bash
kubectl patch configmap cilium-config -n kube-system --type merge -p '{"data":{"enable-node-port":"true"}}'
kubectl rollout restart deployment/cilium-operator -n kube-system
```

### 4. RBAC Errors in Logs

**Error:**

```
forbidden: User "system:serviceaccount:kube-system:cilium" cannot get resource "secrets" in namespace "cilium-secrets"
```

**Cause:** Missing Role or RoleBinding in secrets namespace

**Solution:** Re-run Step 3 or Step 4 from Manual Configuration Guide

---

## References

- [Cilium Gateway API Documentation](https://docs.cilium.io/en/stable/network/servicemesh/gateway-api/)
- [Gateway API Specification](https://gateway-api.sigs.k8s.io/)
- [Cilium Helm Chart Source](https://github.com/cilium/cilium/tree/main/install/kubernetes/cilium)
- [Cilium NodePort Requirements](https://docs.cilium.io/en/stable/network/kubernetes/kubeproxy-free/)

---

**Last Updated:** December 6, 2025  
**Cilium Version:** 1.18.4  
**Gateway API Version:** v1.2.0
