#!/bin/bash
# Build and deploy custom Cilium image with gateway-api-hostnetwork-enabled support
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CILIUM_DIR="$(dirname "$SCRIPT_DIR")"

# Configuration
REGISTRY="${REGISTRY:-acnpublic.azurecr.io}"
ACCOUNT="${ACCOUNT:-matmerr}"
NAMESPACE="${NAMESPACE:-kube-system}"

cd "$CILIUM_DIR"

# Get version info
VERSION=$(cat VERSION)
GIT_SHA=$(git rev-parse --short HEAD)
IMAGE_TAG="${VERSION}-${GIT_SHA}-hostnet"
FULL_IMAGE="${REGISTRY}/${ACCOUNT}/cilium:${IMAGE_TAG}"

echo "================================================"
echo "Cilium Gateway API Hostnetwork Build"
echo "================================================"
echo "Version:    $VERSION"
echo "Git SHA:    $GIT_SHA"
echo "Image Tag:  $IMAGE_TAG"
echo "Full Image: $FULL_IMAGE"
echo "================================================"

# Parse arguments
BUILD=false
PUSH=false
DEPLOY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --build)   BUILD=true; shift ;;
        --push)    PUSH=true; shift ;;
        --deploy)  DEPLOY=true; shift ;;
        --all)     BUILD=true; PUSH=true; DEPLOY=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--build] [--push] [--deploy] [--all]"
            echo ""
            echo "Options:"
            echo "  --build   Build the Docker image"
            echo "  --push    Push image to registry"
            echo "  --deploy  Update daemonset with new image"
            echo "  --all     Do all of the above"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if ! $BUILD && ! $PUSH && ! $DEPLOY; then
    echo "No action specified. Use --build, --push, --deploy, or --all"
    exit 1
fi

# Build
if $BUILD; then
    echo ""
    echo ">>> Building Docker image..."
    make docker-cilium-image \
        DOCKER_IMAGE_TAG="${IMAGE_TAG}" \
        DOCKER_DEV_ACCOUNT="${ACCOUNT}"
    
    echo ""
    echo ">>> Tagging image..."
    docker tag "cilium/cilium:${IMAGE_TAG}" "${FULL_IMAGE}"
fi

# Push
if $PUSH; then
    echo ""
    echo ">>> Pushing image to registry..."
    docker push "${FULL_IMAGE}"
fi

# Deploy
if $DEPLOY; then
    echo ""
    echo ">>> Updating daemonset..."
    kubectl set image daemonset/cilium -n "${NAMESPACE}" \
        cilium-agent="${FULL_IMAGE}"
    
    echo ""
    echo ">>> Waiting for rollout..."
    kubectl rollout status daemonset/cilium -n "${NAMESPACE}" --timeout=300s
    
    echo ""
    echo ">>> Current pods:"
    kubectl get pods -n "${NAMESPACE}" -l k8s-app=cilium
fi

echo ""
echo "================================================"
echo "Done!"
echo "Image: ${FULL_IMAGE}"
echo "================================================"
