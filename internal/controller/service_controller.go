/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"github.com/guu13/swift-network/internal/handler"

	v1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// ServiceReconciler reconciles a Service object
type ServiceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=guu.github.com,resources=Services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=guu.github.com,resources=Services/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=guu.github.com,resources=Services/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Service object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.16.3/pkg/reconcile

var action string

func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log.FromContext(ctx)
	fmt.Println("Service Reconcile", req.Namespace, req.Name, action)
	// TODO(user): your logic here
	service := new(v1.Service)
	if err := r.Get(ctx, client.ObjectKey{Name: req.Name, Namespace: req.Namespace}, service); err != nil {

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	//fmt.Println("Service : ", service)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {

	return ctrl.NewControllerManagedBy(mgr).Watches(&v1.Service{}, &handler.EnqueueRequestForCustom{}).
		For(&v1.Service{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(createEvent event.CreateEvent) bool {
				newService := createEvent.Object.(*v1.Service)
				action = "CreateFunc " + newService.Name
				fmt.Println("CreateFunc")
				return true
			},
			UpdateFunc: func(updateEvent event.UpdateEvent) bool {

				action = "UpdateFunc"

				newService := updateEvent.ObjectNew.(*v1.Service)
				oldService := updateEvent.ObjectOld.(*v1.Service)

				fmt.Println("UpdateFunc ", oldService, newService)
				return true
			},
			DeleteFunc: func(deleteEvent event.DeleteEvent) bool {

				action = "DeleteFunc"

				fmt.Println("DeleteFunc")
				return true
			},
		}).
		Complete(r)
}
