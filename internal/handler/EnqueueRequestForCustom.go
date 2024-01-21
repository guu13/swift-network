package handler

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type empty struct{}

var _ = &EnqueueRequestForCustom{}

// EnqueueRequestForCustom enqueues a Request containing the Name and Namespace of the object that is the source of the Event.
// (e.g. the created / deleted / updated objects Name and Namespace).  handler.EnqueueRequestForObject is used by almost all
// Controllers that have associated Resources (e.g. CRDs) to reconcile the associated Resource.
type EnqueueRequestForCustom struct{}

// Create implements EventHandler.
func (e *EnqueueRequestForCustom) Create(ctx context.Context, evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	fmt.Println("EnqueueRequestForCustom Create")
	if evt.Object == nil {
		fmt.Println("CreateEvent received with no metadata", "event", evt)
		return
	}
	q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
		Name:      evt.Object.GetName(),
		Namespace: evt.Object.GetNamespace(),
	}})
}

// Update implements EventHandler.
func (e *EnqueueRequestForCustom) Update(ctx context.Context, evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	fmt.Println("EnqueueRequestForCustom Update")
	switch {
	case evt.ObjectNew != nil:
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      evt.ObjectNew.GetName(),
			Namespace: evt.ObjectNew.GetNamespace(),
		}})
	case evt.ObjectOld != nil:
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      evt.ObjectOld.GetName(),
			Namespace: evt.ObjectOld.GetNamespace(),
		}})
	default:
		fmt.Println("UpdateEvent received with no metadata", "event", evt)
	}
}

// Delete implements EventHandler.
func (e *EnqueueRequestForCustom) Delete(ctx context.Context, evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	fmt.Println("EnqueueRequestForCustom Delete")
	if evt.Object == nil {
		fmt.Println("DeleteEvent received with no metadata", "event", evt)
		return
	}
	q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
		Name:      evt.Object.GetName(),
		Namespace: evt.Object.GetNamespace(),
	}})
}

// Generic implements EventHandler.
func (e *EnqueueRequestForCustom) Generic(ctx context.Context, evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	if evt.Object == nil {
		fmt.Println(nil, "GenericEvent received with no metadata", "event", evt)
		return
	}
	q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
		Name:      evt.Object.GetName(),
		Namespace: evt.Object.GetNamespace(),
	}})
}
