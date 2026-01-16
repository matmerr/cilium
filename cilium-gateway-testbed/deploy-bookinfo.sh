#!/bin/bash
# Deploy bookinfo sample application and Gateway resources
set -e

NAMESPACE="${NAMESPACE:-kube-system}"

echo ">>> Deploying Bookinfo application..."
kubectl apply -n "${NAMESPACE}" -f https://raw.githubusercontent.com/istio/istio/release-1.28/samples/bookinfo/platform/kube/bookinfo.yaml

echo ""
echo ">>> Creating GatewayClass..."
cat <<EOF | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: cilium
spec:
  controllerName: io.cilium/gateway-controller
EOF

echo ""
echo ">>> Creating Gateway (port 8080)..."
cat <<EOF | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: bookinfo-gateway
  namespace: ${NAMESPACE}
spec:
  gatewayClassName: cilium
  listeners:
  - name: http
    protocol: HTTP
    port: 8080
    allowedRoutes:
      namespaces:
        from: All
EOF

echo ""
echo ">>> Creating HTTPRoute..."
cat <<EOF | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: bookinfo
  namespace: ${NAMESPACE}
spec:
  parentRefs:
  - name: bookinfo-gateway
  rules:
  - matches:
    - path:
        type: Exact
        value: /productpage
    - path:
        type: PathPrefix
        value: /static
    - path:
        type: Exact
        value: /login
    - path:
        type: Exact
        value: /logout
    - path:
        type: PathPrefix
        value: /api/v1/products
    backendRefs:
    - name: productpage
      port: 9080
EOF

echo ""
echo ">>> Waiting for pods..."
kubectl wait --for=condition=ready pod -l app=productpage -n "${NAMESPACE}" --timeout=120s || true

echo ""
echo ">>> Status:"
kubectl get gateway,httproute -n "${NAMESPACE}"
kubectl get svc -n "${NAMESPACE}" | grep -E "gateway|productpage"

echo ""
echo "Done! Test with: ./test.sh"
