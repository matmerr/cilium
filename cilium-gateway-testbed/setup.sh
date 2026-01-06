#!/bin/bash
set -e

TESTBED_DIR="$HOME/cilium-gateway-testbed"

echo "===================================="
echo "Cilium Gateway API Setup Script"
echo "===================================="
echo

# Check if kind cluster exists
if ! kubectl cluster-info &> /dev/null; then
    echo "Error: No Kubernetes cluster found. Please create a kind cluster first."
    echo "Run: make kind"
    exit 1
fi

echo "✓ Kubernetes cluster is running"
echo

# Install Gateway API CRDs
echo "Installing Gateway API CRDs..."
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_referencegrants.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_grpcroutes.yaml

echo "✓ Gateway API CRDs installed"
echo

# Enable Gateway API in Cilium
echo "Enabling Gateway API in Cilium..."
helm upgrade cilium cilium/cilium \
  --namespace kube-system \
  --reuse-values \
  --set gatewayAPI.enabled=true \
  --set nodePort.enabled=true

echo "✓ Gateway API enabled in Cilium"
echo

# Restart Cilium operator
echo "Restarting Cilium operator..."
kubectl -n kube-system rollout restart deployment/cilium-operator
kubectl -n kube-system rollout status deployment/cilium-operator --timeout=2m

echo "✓ Cilium operator restarted"
echo

# Apply Gateway API resources
echo "Applying Gateway API test resources..."
kubectl apply -f "$TESTBED_DIR/01-gatewayclass.yaml"
kubectl apply -f "$TESTBED_DIR/02-gateway.yaml"
kubectl apply -f "$TESTBED_DIR/03-echo-app.yaml"
kubectl apply -f "$TESTBED_DIR/04-httproute.yaml"

echo "✓ Gateway API resources applied"
echo

# Wait for echo pods
echo "Waiting for echo pods to be ready..."
kubectl wait --for=condition=ready pod -l app=echo -n default --timeout=2m

echo "✓ Echo pods are ready"
echo

# Display status
echo
echo "===================================="
echo "Setup Complete!"
echo "===================================="
echo
echo "Resources created in namespace: default"
echo

kubectl get gatewayclass
echo
kubectl get gateway -n default
echo
kubectl get httproute -n default
echo
kubectl get pods -l app=echo -n default
echo

echo "Gateway Service:"
kubectl get svc cilium-gateway-my-gateway -n default
echo

echo "===================================="
echo "Testing Instructions:"
echo "===================================="
echo
echo "1. Test from inside the cluster:"
echo "   kubectl run test --image=curlimages/curl --rm -it --restart=Never -- curl http://cilium-gateway-my-gateway.default/echo"
echo
echo "2. Port forward to test from your host:"
echo "   kubectl port-forward svc/cilium-gateway-my-gateway -n default 8080:80"
echo "   # Then in another terminal:"
echo "   curl http://localhost:8080/echo"
echo
echo "3. View Gateway status:"
echo "   kubectl describe gateway my-gateway -n default"
echo
echo "4. View HTTPRoute status:"
echo "   kubectl describe httproute echo-route -n default"
echo
echo "5. Check Cilium Envoy Config:"
echo "   kubectl get ciliumenvoyconfig -A"
echo
