package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {

	kubeconfig := filepath.Join(
		os.Getenv("HOME"), ".kube", "config",
	)
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatal(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	// 创建一个Watcher，用于监听服务的更改
	watcher := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "services", corev1.NamespaceAll, fields.Everything())

	// 使用SharedInformer创建Watcher
	_, controller := cache.NewInformer(
		watcher,
		&corev1.Service{},
		time.Second*0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				service := obj.(*corev1.Service)
				fmt.Printf("Service added: %s\n", service)
			},
			DeleteFunc: func(obj interface{}) {
				service := obj.(*corev1.Service)
				fmt.Printf("Service deleted: %s\n", service)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldService := oldObj.(*corev1.Service)
				newService := newObj.(*corev1.Service)
				fmt.Printf("Service updated: old: %s , new: %s\n", oldService, newService)
			},
		},
	)

	// 运行控制器
	stop := make(chan struct{})
	defer close(stop)
	go controller.Run(stop)

	// 阻塞主线程以保持程序运行
	select {}

}
