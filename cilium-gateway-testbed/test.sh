#!/bin/bash

echo "Testing Gateway API..."
echo

GATEWAY_IP=$(kubectl get svc cilium-gateway-my-gateway -n default -o jsonpath='{.spec.loadBalancer.ingress[0].ip}')
echo "Gateway LoadBalancer IP: $GATEWAY_IP"
echo

echo "Testing agnhost netexec endpoints:"
echo

echo "1. Test /hostname endpoint:"
curl --max-time 5 http://${GATEWAY_IP}/hostname 2>&1 || echo "Failed to connect"
echo

echo "2. Test root endpoint (returns timestamp):"
curl --max-time 5 http://${GATEWAY_IP}/ 2>&1 || echo "Failed to connect"
echo

echo "3. Test /clientip endpoint:"
curl --max-time 5 http://${GATEWAY_IP}/clientip 2>&1 || echo "Failed to connect"
echo

echo "Note: If all tests fail, the Gateway may not be properly configured."
echo "Check the status with: cd ~/cilium-gateway-testbed && ./status.sh"
