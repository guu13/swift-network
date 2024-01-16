package main

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

func main() {

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	// 1. init Manager
	mgr, _ := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	// 2. init Reconciler（Controller）
	controller, _ := controller.New("myController", mgr, controller.Options{})
	_ = controller.Watch(source.Kind{mgr.GetCache(), &corev1.Pod{}}, &handler.EnqueueRequestForObject{}, predicate.Funcs{
		CreateFunc: func(event event.CreateEvent) bool {

			fmt.Println("CreateFunc")
			return true
		},
		UpdateFunc: func(updateEvent event.UpdateEvent) bool {

			fmt.Println("UpdateFunc")
			return true
		},
		DeleteFunc: func(deleteEvent event.DeleteEvent) bool {

			fmt.Println("DeleteFunc")
			return true
		},
	})
	// 3. start Manager
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
	}

	// 阻塞主线程以保持程序运行
	select {}

}
