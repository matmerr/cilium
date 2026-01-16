#!/bin/bash
# Test Gateway API connectivity
set -e

NAMESPACE="${NAMESPACE:-kube-system}"

echo "================================================"
echo "Gateway API Connectivity Test"
echo "================================================"

# Get Gateway service IP
GATEWAY_SVC="cilium-gateway-bookinfo-gateway"
GATEWAY_IP=$(kubectl get svc "${GATEWAY_SVC}" -n "${NAMESPACE}" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")

if [ -z "$GATEWAY_IP" ]; then
    echo "ERROR: Gateway service not found. Looking for available gateways..."
    kubectl get svc -n "${NAMESPACE}" | grep gateway
    exit 1
fi

echo "Gateway Service: ${GATEWAY_SVC}"
echo "Gateway ClusterIP: ${GATEWAY_IP}:8080"
echo ""

# Test 1: Direct service (should work)
echo ">>> Test 1: Direct service access (productpage:9080)"
DIRECT_RESULT=$(kubectl run test-direct-$$ --rm -i --restart=Never --image=curlimages/curl -- \
    curl -s -o /dev/null -w "%{http_code}" http://productpage.${NAMESPACE}:9080/productpage 2>/dev/null || echo "FAILED")
echo "Result: HTTP ${DIRECT_RESULT}"
if [ "$DIRECT_RESULT" = "200" ]; then
    echo "✅ Direct service is healthy"
else
    echo "❌ Direct service FAILED"
fi
echo ""

# Test 2: Gateway (may return 500 due to known issue)
echo ">>> Test 2: Gateway access (${GATEWAY_IP}:8080)"
GATEWAY_RESULT=$(kubectl run test-gateway-$$ --rm -i --restart=Never --image=curlimages/curl -- \
    curl -s -o /dev/null -w "%{http_code}" http://${GATEWAY_IP}:8080/productpage 2>/dev/null || echo "FAILED")
echo "Result: HTTP ${GATEWAY_RESULT}"
if [ "$GATEWAY_RESULT" = "200" ]; then
    echo "✅ Gateway is working"
else
    echo "❌ Gateway returned ${GATEWAY_RESULT}"
    echo ""
    echo "NOTE: HTTP 500 is expected due to known issue:"
    echo "  Envoy in hostNetwork cannot reach Azure CNI pod IPs"
fi
echo ""

# Summary
echo "================================================"
echo "Summary"
echo "================================================"
echo "Direct Service: HTTP ${DIRECT_RESULT}"
echo "Gateway/Envoy:  HTTP ${GATEWAY_RESULT}"
echo ""
if [ "$GATEWAY_RESULT" = "500" ] && [ "$DIRECT_RESULT" = "200" ]; then
    echo "Known Issue: hostNetwork Envoy cannot route to Azure CNI pods"
fi
