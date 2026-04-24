// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package main is the operator binary for delegated IPAM testing.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/cilium/test/delegated-ipam/api"
	"github.com/cilium/cilium/test/delegated-ipam/operator"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	parentSubnet := os.Getenv("PARENT_SUBNET")
	if parentSubnet == "" {
		log.Fatal("PARENT_SUBNET environment variable is required (e.g. 10.0.0.0/16)")
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to get in-cluster config: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create kubernetes client: %v", err)
	}

	dc, err := dynamic.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create dynamic client: %v", err)
	}

	ipamClient := api.NewClientFromDynamic(dc)

	ctrl, err := operator.NewController(kubeClient, ipamClient, parentSubnet)
	if err != nil {
		log.Fatalf("Failed to create controller: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Println("Shutting down operator...")
		cancel()
	}()

	log.Printf("Starting delegated IPAM test operator with subnet %s", parentSubnet)
	if err := ctrl.Run(ctx); err != nil {
		log.Fatalf("Controller error: %v", err)
	}
}
