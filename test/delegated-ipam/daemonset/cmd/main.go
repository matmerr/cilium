// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package main is the DaemonSet binary for delegated IPAM IPAM testing.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/cilium/test/delegated-ipam/api"
	"github.com/cilium/cilium/test/delegated-ipam/daemonset"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func main() {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Fatal("NODE_NAME environment variable is required")
	}

	socketPath := os.Getenv("SOCKET_PATH")
	if socketPath == "" {
		socketPath = api.SocketPath
	}

	healthPort := os.Getenv("HEALTH_PORT")
	if healthPort == "" {
		healthPort = "19876"
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to get in-cluster config: %v", err)
	}

	dc, err := dynamic.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create dynamic client: %v", err)
	}

	client := api.NewClientFromDynamic(dc)
	srv := daemonset.NewServer(nodeName)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		srv.Shutdown(ctx)
		cancel()
	}()

	// Start TCP health check server immediately (before CRD is ready)
	go func() {
		log.Printf("Starting health check server on :%s", healthPort)
		httpSrv := &http.Server{
			Addr:    ":" + healthPort,
			Handler: srv.Handler(),
		}
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Health server error: %v", err)
		}
	}()

	// Poll CRD until our node's subnet is available
	log.Printf("Waiting for node %s subnet allocation in CiliumTestIPAM...", nodeName)
	for {
		if ctx.Err() != nil {
			log.Fatal("Context cancelled while waiting for CRD")
		}

		ipam, err := client.Get(ctx, api.CRDName)
		if err != nil {
			log.Printf("Waiting for CiliumTestIPAM: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		nodeStatus, ok := ipam.Status.Nodes[nodeName]
		if !ok {
			log.Printf("Node %q not yet in CiliumTestIPAM status, retrying...", nodeName)
			time.Sleep(2 * time.Second)
			continue
		}

		if err := srv.Configure(nodeStatus); err != nil {
			log.Printf("Failed to configure: %v, retrying...", err)
			time.Sleep(2 * time.Second)
			continue
		}

		log.Printf("Configured with subnet %s for node %s", nodeStatus.Subnet, nodeName)
		break
	}

	log.Printf("Starting IPAM DaemonSet for node %s on %s", nodeName, socketPath)
	if err := srv.ListenAndServeUnix(socketPath); err != nil && ctx.Err() == nil {
		log.Fatalf("Server error: %v", err)
	}
}
