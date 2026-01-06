#!/bin/bash
set -e

echo "Cleaning up Gateway API resources..."

kubectl delete -f ~/cilium-gateway-testbed/04-httproute.yaml --ignore-not-found=true
kubectl delete -f ~/cilium-gateway-testbed/03-echo-app.yaml --ignore-not-found=true
kubectl delete -f ~/cilium-gateway-testbed/02-gateway.yaml --ignore-not-found=true
kubectl delete -f ~/cilium-gateway-testbed/01-gatewayclass.yaml --ignore-not-found=true

echo "✓ Gateway API resources cleaned up"
echo

echo "Gateway API CRDs and Cilium configuration are still installed."
echo "To completely remove Gateway API support:"
echo "  helm upgrade cilium cilium/cilium --namespace kube-system --reuse-values --set gatewayAPI.enabled=false"
echo "  kubectl delete crd gatewayclasses.gateway.networking.k8s.io gateways.gateway.networking.k8s.io httproutes.gateway.networking.k8s.io referencegrants.gateway.networking.k8s.io grpcroutes.gateway.networking.k8s.io"
