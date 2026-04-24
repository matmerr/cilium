// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"context"
	"log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

// Run starts the controller. It watches nodes and allocates subnets.
// Blocks until the context is cancelled.
func (c *Controller) Run(ctx context.Context) error {
	if err := c.loadExistingAllocations(ctx); err != nil {
		log.Printf("Warning: failed to load existing allocations: %v", err)
	}

	factory := informers.NewSharedInformerFactory(c.kubeClient, 0)
	nodeInformer := factory.Core().V1().Nodes().Informer()

	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}
			c.handleNode(ctx, node)
		},
		UpdateFunc: func(_, newObj interface{}) {
			node, ok := newObj.(*corev1.Node)
			if !ok {
				return
			}
			c.handleNode(ctx, node)
		},
	})

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())

	log.Printf("Operator controller running, watching nodes")
	<-ctx.Done()
	return nil
}
