#!/bin/bash

echo "===================================="
echo "Gateway API Status Check"
echo "===================================="
echo

echo "1. Gateway API CRDs:"
kubectl get crd | grep gateway.networking.k8s.io
echo

echo "2. GatewayClass:"
kubectl get gatewayclass
echo

echo "3. Gateway:"
kubectl get gateway -A
echo

echo "4. HTTPRoute:"
kubectl get httproute -A
echo

echo "5. Backend Pods:"
kubectl get pods -l app=echo -n default
echo

echo "6. Gateway Service:"
kubectl get svc cilium-gateway-my-gateway -n default
echo

echo "7. Cilium Envoy Config:"
kubectl get ciliumenvoyconfig -A
echo

echo "8. Detailed Gateway Status:"
kubectl describe gateway my-gateway -n default | tail -30
echo

echo "9. Detailed HTTPRoute Status:"
kubectl describe httproute echo-route -n default | tail -30
echo
