# Cilium Gateway API Hostnetwork Testbed

This testbed explores running Cilium Gateway API with `hostNetwork=true` and `delegated-plugin` IPAM (Azure CNI).

**Current Status**: ⚠️ Gateway accepts traffic but returns HTTP 500 due to Envoy unable to reach backend pods.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Host Network                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Cilium Agent Pod (hostNetwork=true)                      │   │
│  │   ┌────────────────────────────────────────────────────┐ │   │
│  │   │ Embedded Envoy (listening on 0.0.0.0:8080)         │ │   │
│  │   │   - Receives traffic via ClusterIP service         │ │   │
│  │   │   - Cannot route to Azure CNI pod IPs ❌           │ │   │
│  │   └────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ (HTTP 500 - no route to backend)
┌─────────────────────────────────────────────────────────────────┐
│                      Pod Network (Azure CNI)                    │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────────────┐ │
│  │ productpage│  │  details   │  │ ratings, reviews (v1/v2/v3)│ │
│  │  :9080     │  │   :9080    │  │          :9080             │ │
│  └────────────┘  └────────────┘  └────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

### Cilium ConfigMap Settings

```yaml
gateway-api-hostnetwork-enabled: "true"
enable-gateway-api: "true"
enable-envoy-config: "true"
ipam: delegated-plugin
kube-proxy-replacement: "true"
```

### Custom Cilium Image

```
acnpublic.azurecr.io/matmerr/cilium:v1.18.2-5bd307a8f6-hostnet
```

## Code Changes

Three files were modified to allow `enable-envoy-config` with `delegated-plugin` IPAM when `gateway-api-hostnetwork-enabled=true`:

1. **pkg/option/config.go** - Added option constant and validation bypass
2. **daemon/cmd/daemon_main.go** - Skip ingress endpoint creation
3. **daemon/cmd/ipam.go** - Skip ingress IP allocation

## Known Issue

**Problem**: HTTP 500 when accessing through Gateway

**Root Cause**:

- Cilium agents run with `hostNetwork=true`
- Embedded Envoy runs in host network namespace
- Backend pods have IPs from Azure CNI (delegated-plugin)
- Host network namespace lacks routes to Azure CNI pod network
- Envoy cannot reach backend pod IPs

**Evidence**:

```
Direct service access:  HTTP 200 ✅
Gateway/Envoy access:   HTTP 500 ❌
```

## Directory Structure

```
cilium-gateway-testbed/
├── README.md                    # This file
├── setup.sh                     # Main setup script
├── status.sh                    # Check status of all resources
├── test.sh                      # Test the Gateway
├── cleanup.sh                   # Clean up resources
├── deploy-custom-build.sh       # Build and deploy custom Cilium
├── 01-gatewayclass.yaml        # GatewayClass definition
├── 02-gateway.yaml             # Gateway definition
├── 03-echo-app.yaml            # Sample echo application
└── 04-httproute.yaml           # HTTPRoute configuration
```

## Quick Commands

### Check Gateway Status

```bash
./status.sh
# or manually:
kubectl get gateway,httproute -A
kubectl get svc -n kube-system | grep gateway
```

### Test Gateway vs Direct Service

````bash
./test.sh
# or manually:

```bash
kubectl port-forward svc/cilium-gateway-my-gateway -n default 8080:80 &
curl http://localhost:8080/echo
````

### 4. Cleanup

```bash
./cleanup.sh
```

## Manual Steps

### Apply Resources Individually

```bash
kubectl apply -f 01-gatewayclass.yaml
kubectl apply -f 02-gateway.yaml
kubectl apply -f 03-echo-app.yaml
kubectl apply -f 04-httproute.yaml
```

### Check Gateway Status

```bash
kubectl describe gateway my-gateway -n default
kubectl describe httproute echo-route -n default
```

### View Cilium Envoy Configuration

```bash
kubectl get ciliumenvoyconfig -A
kubectl describe cec cilium-gateway-my-gateway -n default
```

## Troubleshooting

### Check Cilium Operator Logs

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=cilium-operator
```

### Check Cilium Agent Logs

```bash
kubectl logs -n kube-system -l k8s-app=cilium
```

### Check Envoy Logs

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=cilium-envoy
```

### Verify Gateway API is Enabled

```bash
kubectl get cm -n kube-system cilium-config -o yaml | grep gateway
```

## Resources

- [Cilium Gateway API Documentation](https://docs.cilium.io/en/stable/network/servicemesh/gateway-api/gateway-api/)
- [Gateway API Documentation](https://gateway-api.sigs.k8s.io/)
- [Cilium HTTP Example](https://docs.cilium.io/en/stable/network/servicemesh/gateway-api/http/)
