#!/bin/bash

ACN_DIR=${GOPATH}/src/github.com/Azure/azure-container-networking/test/integration
CILIUM_MANIFEST_DIR=/home/matmerr/go/src/github.com/azure-networking/cilium-private/test/manifests
CILIUM_VERSION=v1.18
CILIUM_VERSION_TAG=v1.18.2-251028
CILIUM_IMAGE_REGISTRY=mcr.microsoft.com/containernetworking

REGION=westus2
SUB=9b8218f9-902a-4d20-a65c-e98acec5362f
NAME=matmerr
CLUSTER=$NAME-nonaz-cilium-4
AZMON_NAME=${NAME}aksnetobs11
GRAFANA_NAME=${NAME}aksnetobs11
RESOURCE_GROUP=${CLUSTER}
NAME=$CLUSTER
NODE_COUNT=2
VM_SIZE=Standard_D4s_v3

NODEUPGRADE=NodeImage
AUTOUPGRADE="patch"

az group create --location $REGION --name $RESOURCE_GROUP --subscription $SUB

#Make cluster
set -ex

# Check if cluster already exists
if az aks show -n $CLUSTER -g $RESOURCE_GROUP --subscription $SUB &>/dev/null; then
    echo "Cluster $CLUSTER already exists, pulling kubeconfig only"
    az aks get-credentials -n $CLUSTER -g $RESOURCE_GROUP --subscription $SUB --overwrite-existing
else
    echo "Creating new cluster $CLUSTER"
    az network vnet create -g $RESOURCE_GROUP -l $REGION --name $CLUSTER --address-prefixes 10.0.0.0/9 -o none --subscription $SUB
    az network vnet subnet create -g $RESOURCE_GROUP --vnet-name $CLUSTER --name nodenet --address-prefix 10.0.0.0/12 -o none --subscription $SUB

    az aks create -n $CLUSTER -g $RESOURCE_GROUP -l $REGION \
        --subscription $SUB \
        --auto-upgrade-channel $AUTOUPGRADE \
        --node-os-upgrade-channel $NODEUPGRADE \
        --node-count $NODE_COUNT \
        --node-vm-size $VM_SIZE \
        --load-balancer-sku standard \
        --network-plugin none \
        --network-plugin-mode overlay \
        --pod-cidr 10.128.0.0/9 \
        --dns-service-ip 192.168.0.10 \
        --service-cidr 192.168.0.0/16 \
        --vnet-subnet-id /subscriptions/$SUB/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Network/virtualNetworks/$CLUSTER/subnets/nodenet \
        --no-ssh-key \
        --kube-proxy-config ./aks/kube-proxy.json \
        --yes

    az extension add --name aks-preview
    az aks get-credentials -n $CLUSTER -g $RESOURCE_GROUP --subscription $SUB
fi

kubectl cluster-info
kubectl get po -owide -A

# Install Cilium with Gateway API support
install_cilium() {
    echo "Installing Cilium ${CILIUM_VERSION_TAG} with Gateway API support"
    echo "https://github.com/azure-networking/cilium-private/tree/main/test/manifests/v1.18"

    # Install Cilium CLI if not present
    if ! command -v cilium &> /dev/null; then
        echo "Installing Cilium CLI..."
        CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
        CLI_ARCH=amd64
        if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
        curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
        sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
        sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
        rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
    fi

    # Install Gateway API CRDs (required before Cilium installation)
    echo "Installing Gateway API CRDs v1.2.0..."
    kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
    kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
    kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
    kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_referencegrants.yaml
    kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/standard/gateway.networking.k8s.io_grpcroutes.yaml
    # Optional: TLSRoute for TLS passthrough support
    kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.0/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml

    # Install Cilium with Gateway API enabled using Helm
    echo "Installing Cilium via Helm with Gateway API support..."
    helm repo add cilium https://helm.cilium.io/ || true
    helm repo update

    helm upgrade --install cilium cilium/cilium --version ${CILIUM_VERSION#v} \
        --namespace kube-system \
        --set kubeProxyReplacement=true \
        --set k8sServiceHost="$(kubectl get endpoints kubernetes -o jsonpath='{.subsets[0].addresses[0].ip}')" \
        --set k8sServicePort=443 \
        --set gatewayAPI.enabled=true \
        --set l7Proxy=true \
        --set nodePort.enabled=true

    # Wait for Cilium to be ready
    echo "Waiting for Cilium to be ready..."
    cilium status --wait

    echo "Cilium installation complete with Gateway API support!"
}

# Check if Cilium is already installed
if kubectl get daemonset cilium -n kube-system &>/dev/null; then
    echo "Cilium already installed, checking status..."
    cilium status || true
else
    install_cilium
fi

# Verify Gateway API setup
echo "Verifying Gateway API setup..."
kubectl get gatewayclasses
kubectl get gateways -A
kubectl get httproutes -A
