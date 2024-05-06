package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type ConfigMapWatcher struct {
	log           *slog.Logger
	namespace     string
	name          string
	dynamicClient *dynamic.DynamicClient
}

func New(namespace, name string) (*ConfigMapWatcher, error) {
	k8sConfig, err := k8sConfig()
	if err != nil {
		return nil, err
	}

	config := dynamic.ConfigFor(k8sConfig)
	httpClient, err := rest.HTTPClientFor(config)
	if err != nil {
		return nil, err
	}

	watcher := &ConfigMapWatcher{
		log:       slog.With("namespace", namespace, "name", name),
		namespace: namespace,
		name:      name,
	}

	watcher.dynamicClient, err = dynamic.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, err
	}

	return watcher, nil
}

func (w *ConfigMapWatcher) Get(ctx context.Context) (v1.ConfigMap, error) {
	obj, err := w.dynamicClient.
		Resource(v1.SchemeGroupVersion.WithResource("configmaps")).
		Namespace(w.namespace).
		Get(ctx, w.name, metav1.GetOptions{})
	if err != nil {
		return v1.ConfigMap{}, err
	}

	return TypedEventHandler[v1.ConfigMap]{}.parse(obj)
}

// StartWatching pushes instances of the identified configuration map found in a
// target Kuberentes cluster.
func (w *ConfigMapWatcher) StartWatching(ctx context.Context, dst chan<- v1.ConfigMap) error {
	w.log.Debug("Creating shared informer factory")

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(w.dynamicClient, 0, w.namespace, func(lo *metav1.ListOptions) {
		lo.FieldSelector = fields.OneTermEqualSelector("metadata.name", w.name).String()
	})

	if err := inform(ctx, factory, v1.SchemeGroupVersion.WithResource("configmaps"), TypedEventHandler[v1.ConfigMap]{
		AddFunc: func(cfg v1.ConfigMap) {
			w.log.Debug("ConfigMap added")
		},
		UpdateFunc: func(_, cfg v1.ConfigMap) {
			w.log.Debug("ConfigMap updated")
			dst <- cfg
		},
		DeleteFunc: func(cfg v1.ConfigMap) {
			w.log.Debug("ConfigMap deleted")
		},
	}); err != nil {
		return err
	}

	return nil
}

func k8sConfig() (*rest.Config, error) {
	if cfg := os.Getenv("KUBECONFIG"); cfg != "" {
		return clientcmd.BuildConfigFromFlags("", cfg)
	}

	return rest.InClusterConfig()
}

func inform[T any](ctx context.Context, factory dynamicinformer.DynamicSharedInformerFactory, resource schema.GroupVersionResource, handler TypedEventHandler[T]) error {
	informer := factory.ForResource(resource).Informer()
	if _, err := informer.AddEventHandler(handler); err != nil {
		return err
	}

	go informer.Run(ctx.Done())

	return nil
}

type TypedEventHandler[T any] struct {
	AddFunc    func(T)
	UpdateFunc func(T, T)
	DeleteFunc func(T)
}

func (_ TypedEventHandler[T]) parse(obj any) (t T, err error) {
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.(*unstructured.Unstructured).Object, &t)
	if err != nil {
		slog.Error("Parsing object into type", "type", fmt.Sprintf("%T", t), "error", err)
	}
	return
}

// OnAdd calls AddFunc if it's not nil.
func (t TypedEventHandler[T]) OnAdd(obj interface{}, isInInitialList bool) {
	if t.AddFunc != nil {
		o, err := t.parse(obj)
		if err != nil {
			return
		}

		t.AddFunc(o)
	}
}

// OnUpdate calls UpdateFunc if it's not nil.
func (t TypedEventHandler[T]) OnUpdate(oldObj, newObj interface{}) {
	if t.UpdateFunc != nil {
		o, err := t.parse(oldObj)
		if err != nil {
			return
		}

		n, err := t.parse(newObj)
		if err != nil {
			return
		}

		t.UpdateFunc(o, n)
	}
}

// OnDelete calls DeleteFunc if it's not nil.
func (t TypedEventHandler[T]) OnDelete(obj interface{}) {
	if t.DeleteFunc != nil {
		o, err := t.parse(obj)
		if err != nil {
			return
		}

		t.DeleteFunc(o)
	}
}
