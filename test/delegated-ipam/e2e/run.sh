#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
#
# End-to-end test for delegated IPAM IPAM.
# Sets up a Kind cluster, installs Cilium with delegated-plugin IPAM mode,
# deploys our test IPAM infrastructure, and validates cross-node pod connectivity.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-delegated-ipam-test}"
PARENT_SUBNET="10.244.0.0/16"
CNI_PLUGIN_NAME="cilium-delegated-test-ipam"
SOCKET_PATH="/var/run/cilium/test-ipam.sock"
CILIUM_VERSION="${CILIUM_VERSION:-1.18.6}"
TIMEOUT="${TIMEOUT:-300}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { log "FATAL: $*"; exit 1; }

cleanup() {
    log "Cleaning up..."
    kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
}

# --- Build binaries ---
build_binaries() {
    log "Building CNI IPAM plugin..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -o "${SCRIPT_DIR}/${CNI_PLUGIN_NAME}" \
        "${REPO_ROOT}/test/delegated-ipam/cni/"

    log "Building daemonset binary..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -o "${SCRIPT_DIR}/test-ipam-daemonset" \
        "${REPO_ROOT}/test/delegated-ipam/daemonset/cmd/"

    log "Building operator binary..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -o "${SCRIPT_DIR}/test-ipam-operator" \
        "${REPO_ROOT}/test/delegated-ipam/operator/cmd/"
}

# --- Generate per-node CNI conflist ---
generate_conflist() {
    cat <<EOF
{
  "cniVersion": "0.3.1",
  "name": "cilium",
  "plugins": [
    {
      "type": "cilium-cni",
      "enable-debug": true,
      "log-file": "/var/log/cilium-cni.log",
      "ipam": {
        "type": "${CNI_PLUGIN_NAME}"
      }
    }
  ]
}
EOF
}

# --- Create Kind cluster ---
create_cluster() {
    log "Creating Kind cluster '${CLUSTER_NAME}'..."

    local conflist
    conflist=$(generate_conflist)

    # Write identical conflist for each node (subnet comes from CRD, not conflist)
    for node in kind-control-plane kind-worker kind-worker2; do
        echo "${conflist}" > "${SCRIPT_DIR}/${node}-conflist.json"
    done

    cat <<EOF > "${SCRIPT_DIR}/kind-config.yaml"
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: ${SCRIPT_DIR}/kind-control-plane-conflist.json
        containerPath: /etc/cni/net.d/05-cilium.conflist
  - role: worker
    extraMounts:
      - hostPath: ${SCRIPT_DIR}/kind-worker-conflist.json
        containerPath: /etc/cni/net.d/05-cilium.conflist
  - role: worker
    extraMounts:
      - hostPath: ${SCRIPT_DIR}/kind-worker2-conflist.json
        containerPath: /etc/cni/net.d/05-cilium.conflist
networking:
  disableDefaultCNI: true
  podSubnet: "${PARENT_SUBNET}"
  serviceSubnet: "10.245.0.0/16"
EOF

    kind create cluster --name "${CLUSTER_NAME}" --config "${SCRIPT_DIR}/kind-config.yaml" --wait 0
}

# --- Install CNI plugin binary on all nodes ---
install_cni_plugin() {
    log "Installing CNI IPAM plugin on all nodes..."
    for node in $(kind get nodes --name "${CLUSTER_NAME}"); do
        docker cp "${SCRIPT_DIR}/${CNI_PLUGIN_NAME}" "${node}:/opt/cni/bin/${CNI_PLUGIN_NAME}"
        docker exec "${node}" chmod +x "/opt/cni/bin/${CNI_PLUGIN_NAME}"
        docker exec "${node}" mkdir -p "$(dirname "${SOCKET_PATH}")"
    done
}

# --- Apply CRD ---
apply_crd() {
    log "Applying CiliumTestIPAM CRD..."
    kubectl apply -f "${SCRIPT_DIR}/crd.yaml"
}

# --- Create CiliumTestIPAM CR ---
create_ipam_cr() {
    log "Creating CiliumTestIPAM resource..."
    cat <<EOF | kubectl apply -f -
apiVersion: test.cilium.io/v1alpha1
kind: CiliumTestIPAM
metadata:
  name: default
spec:
  subnet: "${PARENT_SUBNET}"
EOF
}

# --- Deploy operator and daemonset ---
deploy_infra() {
    log "Deploying test IPAM operator and daemonset..."

    for node in $(kind get nodes --name "${CLUSTER_NAME}"); do
        docker cp "${SCRIPT_DIR}/test-ipam-daemonset" "${node}:/usr/local/bin/test-ipam-daemonset"
        docker exec "${node}" chmod +x /usr/local/bin/test-ipam-daemonset
        docker cp "${SCRIPT_DIR}/test-ipam-operator" "${node}:/usr/local/bin/test-ipam-operator"
        docker exec "${node}" chmod +x /usr/local/bin/test-ipam-operator
    done

    kubectl apply -f "${SCRIPT_DIR}/rbac.yaml"
    kubectl apply -f "${SCRIPT_DIR}/operator-deployment.yaml"
    kubectl apply -f "${SCRIPT_DIR}/daemonset.yaml"
}

# --- Install Cilium ---
install_cilium() {
    log "Installing Cilium ${CILIUM_VERSION} with delegated-plugin IPAM..."
    helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
    helm repo update cilium

    helm install cilium cilium/cilium \
        --version "${CILIUM_VERSION}" \
        --namespace kube-system \
        --set ipam.mode=delegated-plugin \
        --set cni.customConf=true \
        --set routingMode=native \
        --set autoDirectNodeRoutes=true \
        --set ipv4NativeRoutingCIDR="${PARENT_SUBNET}" \
        --set endpointRoutes.enabled=true \
        --set endpointHealthChecking.enabled=false \
        --set "extraArgs[0]=--local-router-ipv4=169.254.23.0" \
        --set enableIPv4Masquerade=true \
        --set bpf.masquerade=true \
        --set ipMasqAgent.enabled=true \
        --set nodePort.enabled=true \
        --set ipv6.enabled=false \
        --set enableEnvoyConfig=false \
        --set operator.replicas=1
}

# --- Wait for infrastructure to be ready ---
wait_for_infra() {
    log "Waiting for operator to be ready..."
    kubectl rollout status deployment/cilium-delegated-ipam-operator -n kube-system --timeout="${TIMEOUT}s"

    log "Waiting for daemonset to be ready..."
    kubectl rollout status daemonset/cilium-delegated-ipam -n kube-system --timeout="${TIMEOUT}s"

    log "Waiting for CiliumTestIPAM status to have node allocations..."
    local elapsed=0
    while [ $elapsed -lt $TIMEOUT ]; do
        local node_count
        node_count=$(kubectl get ciliumtestipam default -o jsonpath='{.status.nodes}' 2>/dev/null \
            | python3 -c "import sys,json; print(len(json.loads(sys.stdin.read() or '{}')))" 2>/dev/null \
            || echo 0)
        local expected_nodes
        expected_nodes=$(kubectl get nodes --no-headers | wc -l)
        if [ "$node_count" -ge "$expected_nodes" ]; then
            log "All ${node_count} nodes have subnet allocations"
            break
        fi
        log "  ${node_count}/${expected_nodes} nodes have allocations..."
        elapsed=$((elapsed + 5))
        kubectl wait --for=condition=Ready nodes --all --timeout=5s 2>/dev/null || true
    done

    if [ $elapsed -ge $TIMEOUT ]; then
        die "Timed out waiting for node subnet allocations"
    fi

    log "Waiting for Cilium to be ready..."
    kubectl rollout status daemonset/cilium -n kube-system --timeout="${TIMEOUT}s"
    kubectl rollout status deployment/cilium-operator -n kube-system --timeout="${TIMEOUT}s"
}

# --- Set up cross-node routes ---
# In delegated-plugin IPAM mode, Cilium doesn't automatically learn remote pod
# CIDRs from the CiliumTestIPAM CR. We install static routes on each Kind node
# so that pod traffic destined for another node's subnet is forwarded correctly.
setup_cross_node_routes() {
    log "Setting up cross-node routes..."

    # Build arrays of node names, docker IPs, and pod CIDRs
    local -a names ips cidrs
    while IFS= read -r line; do
        local name ip cidr
        name=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $6}')
        cidr=$(kubectl get node "$name" -o jsonpath='{.spec.podCIDR}')
        names+=("$name")
        ips+=("$ip")
        cidrs+=("$cidr")
        log "  Node ${name}: IP=${ip}, podCIDR=${cidr}"
    done < <(kubectl get nodes -o wide --no-headers)

    # For each node, add routes to every other node's pod CIDR
    for i in "${!names[@]}"; do
        for j in "${!names[@]}"; do
            if [ "$i" != "$j" ] && [ -n "${cidrs[$j]}" ]; then
                local container="${names[$i]}"
                local dest="${cidrs[$j]}"
                local via="${ips[$j]}"
                docker exec "${container}" ip route replace "${dest}" via "${via}" dev eth0 2>/dev/null || true
            fi
        done
    done

    log "Cross-node routes installed"
}

# --- Deploy test pods ---
deploy_test_pods() {
    log "Deploying agnhost test pods on different worker nodes..."

    local workers
    workers=($(kubectl get nodes --no-headers -l '!node-role.kubernetes.io/control-plane' -o name | sed 's|node/||'))

    if [ ${#workers[@]} -lt 2 ]; then
        die "Need at least 2 worker nodes, got ${#workers[@]}"
    fi

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-1
  labels:
    app: delegated-ipam-test
spec:
  nodeName: ${workers[0]}
  containers:
    - name: agnhost
      image: registry.k8s.io/e2e-test-images/agnhost:2.43
      command: ["/agnhost", "netexec", "--http-port=8080"]
  tolerations:
    - operator: Exists
  terminationGracePeriodSeconds: 0
---
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-2
  labels:
    app: delegated-ipam-test
spec:
  nodeName: ${workers[1]}
  containers:
    - name: agnhost
      image: registry.k8s.io/e2e-test-images/agnhost:2.43
      command: ["/agnhost", "netexec", "--http-port=8080"]
  tolerations:
    - operator: Exists
  terminationGracePeriodSeconds: 0
EOF

    log "Waiting for test pods to be ready..."
    kubectl wait --for=condition=Ready pod/test-pod-1 pod/test-pod-2 --timeout="${TIMEOUT}s"
}

# --- Run connectivity test ---
run_connectivity_test() {
    log "=== Running connectivity test ==="

    local pod1_ip pod2_ip pod1_node pod2_node
    pod1_ip=$(kubectl get pod test-pod-1 -o jsonpath='{.status.podIP}')
    pod2_ip=$(kubectl get pod test-pod-2 -o jsonpath='{.status.podIP}')
    pod1_node=$(kubectl get pod test-pod-1 -o jsonpath='{.spec.nodeName}')
    pod2_node=$(kubectl get pod test-pod-2 -o jsonpath='{.spec.nodeName}')

    log "Pod 1: ${pod1_ip} on ${pod1_node}"
    log "Pod 2: ${pod2_ip} on ${pod2_node}"

    # Verify IPs are from our IPAM range
    if [[ ! "${pod1_ip}" =~ ^10\.244\. ]]; then
        die "Pod 1 IP ${pod1_ip} is not from our IPAM range ${PARENT_SUBNET}"
    fi
    if [[ ! "${pod2_ip}" =~ ^10\.244\. ]]; then
        die "Pod 2 IP ${pod2_ip} is not from our IPAM range ${PARENT_SUBNET}"
    fi
    log "✓ Both pods have IPs from delegated IPAM range"

    # Test cross-node ICMP ping (both directions)
    log "Testing ping: pod-1 (${pod1_ip}) → pod-2 (${pod2_ip})..."
    kubectl exec test-pod-1 -- ping -c 3 -W 5 "${pod2_ip}" || die "Pod 1 → Pod 2 ping FAILED"
    log "✓ Pod 1 → Pod 2 ping works"

    log "Testing ping: pod-2 (${pod2_ip}) → pod-1 (${pod1_ip})..."
    kubectl exec test-pod-2 -- ping -c 3 -W 5 "${pod1_ip}" || die "Pod 2 → Pod 1 ping FAILED"
    log "✓ Pod 2 → Pod 1 ping works"

    # Test TCP connectivity via agnhost netexec
    log "Testing TCP: pod-1 → pod-2:8080..."
    kubectl exec test-pod-1 -- /agnhost connect "${pod2_ip}:8080" --timeout=10s --protocol=tcp \
        || die "Pod 1 → Pod 2 TCP connect FAILED"
    log "✓ Pod 1 → Pod 2 TCP works"

    log "Testing TCP: pod-2 → pod-1:8080..."
    kubectl exec test-pod-2 -- /agnhost connect "${pod1_ip}:8080" --timeout=10s --protocol=tcp \
        || die "Pod 2 → Pod 1 TCP connect FAILED"
    log "✓ Pod 2 → Pod 1 TCP works"

    log ""
    log "========================================="
    log "✅ E2E TEST PASSED: Cross-node delegated IPAM connectivity verified"
    log "  ICMP: ✓  TCP: ✓  IPAM range: ✓"
    log "========================================="
}

# --- Main ---
main() {
    trap cleanup EXIT

    cd "${REPO_ROOT}"

    build_binaries
    create_cluster
    install_cni_plugin
    apply_crd
    install_cilium
    deploy_infra
    create_ipam_cr
    wait_for_infra
    setup_cross_node_routes
    deploy_test_pods
    run_connectivity_test

    log "Done! Cluster '${CLUSTER_NAME}' is still running for inspection."
    trap - EXIT  # Don't cleanup on success
}

main "$@"
