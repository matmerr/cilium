# Cilium Gateway API Test Bed

This directory contains everything needed to set up and test Cilium's Gateway API support.

## Directory Structure

```
cilium-gateway-testbed/
├── README.md                    # This file
├── setup.sh                     # Main setup script
├── status.sh                    # Check status of all resources
├── test.sh                      # Test the Gateway
├── cleanup.sh                   # Clean up resources
├── 01-gatewayclass.yaml        # GatewayClass definition
├── 02-gateway.yaml             # Gateway definition
├── 03-echo-app.yaml            # Sample echo application
└── 04-httproute.yaml           # HTTPRoute configuration
```

## Quick Start

### 1. Setup

Make sure you have a kind cluster with Cilium installed, then run:

```bash
cd ~/cilium-gateway-testbed
chmod +x *.sh
./setup.sh
```

This will:
- Install Gateway API CRDs
- Enable Gateway API in Cilium
- Deploy a sample echo application
- Create a Gateway and HTTPRoute

### 2. Check Status

```bash
./status.sh
```

### 3. Test

```bash
./test.sh
```

Or manually test with port-forward:

```bash
kubectl port-forward svc/cilium-gateway-my-gateway -n default 8080:80 &
curl http://localhost:8080/echo
```

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
