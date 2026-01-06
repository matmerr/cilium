#!/bin/bash

export HELM_ARGS="\
  --wait \
  --namespace kube-system \
  --set debug.enabled=true \
  --set debug.verbose=envoy \
  --set-string=extraEnv[0].name=CILIUM_FEATURE_METRICS_WITH_DEFAULTS \
  --set-string=extraEnv[0].value=true \
  --set-string=extraEnv[1].name=CILIUM_INVALID_METRIC_VALUE_DETECTOR \
  --set-string=extraEnv[1].value=true \
  --set-string=extraEnv[2].name=CILIUM_SLOG_DUP_ATTR_DETECTOR \
  --set-string=extraEnv[2].value=true \
  --set-string=extraEnv[3].name=KUBE_CACHE_MUTATION_DETECTOR \
  --set-string=extraEnv[3].value=true \
  --set nodeinit.enabled=true \
  --set kubeProxyReplacement=false \
  --set socketLB.enabled=false \
  --set externalIPs.enabled=true \
  --set nodePort.enabled=true \
  --set hostPort.enabled=true \
  --set bpf.masquerade=false \
  --set ipam.mode=kubernetes \
  --set image.repository=quay.io/cilium/cilium-ci \
  --set image.tag=v1.15 \
  --set image.pullPolicy=IfNotPresent \
  --set image.useDigest=false \
  --set operator.image.repository=quay.io/cilium/operator \
  --set operator.image.suffix=-ci \
  --set operator.image.tag=v1.15  \
  --set operator.image.pullPolicy=IfNotPresent \
  --set operator.image.useDigest=false \
  --set prometheus.enabled=true \
  --set operator.prometheus.enabled=true \
  --set hubble.enabled=true \
  --set=hubble.metrics.enabled={dns,drop,tcp,flow,port-distribution,icmp,http}"

helm install cilium ./install/kubernetes/cilium $HELM_ARGS
