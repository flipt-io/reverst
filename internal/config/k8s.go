package config

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func watchK8sConfigMap(ctx context.Context, ch chan<- *TunnelGroups, namespace, name, key string) error {
	config, err := k8sConfig()
	if err != nil {
		return err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	factory := informers.NewFilteredSharedInformerFactory(client, 0, namespace, func(lo *metav1.ListOptions) {
		lo.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	})

	informer := factory.Core().V1().ConfigMaps().Informer()
	informer.AddEventHandler(TypedEventHandler[v1.ConfigMap]{
		logger: slog.With("resource", "configmap"),
		AddFunc: func(cm v1.ConfigMap) {
			tg, err := buildTunnelGroupsFromConfigMap(ctx, cm, key)
			if err != nil {
				slog.Error("Converting ConfigMap into tunnel groups", "error", err)
				return
			}

			ch <- tg
		},
		UpdateFunc: func(_, cm v1.ConfigMap) {
			tg, err := buildTunnelGroupsFromConfigMap(ctx, cm, key)
			if err != nil {
				slog.Error("Converting ConfigMap into tunnel groups", "error", err)
				return
			}

			ch <- tg
		},
	})

	factory.Start(ctx.Done())

	// wait for initial list to complete and watchers to begin before proceeding
	factory.WaitForCacheSync(ctx.Done())

	return nil
}

func buildTunnelGroupsFromConfigMap(ctx context.Context, cfg v1.ConfigMap, key string) (*TunnelGroups, error) {
	raw, ok := cfg.Data[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in ConfigMap", key)
	}

	var groups TunnelGroups
	if err := yaml.Unmarshal([]byte(raw), &groups); err != nil {
		return nil, fmt.Errorf("decoding tunnel groups: %w", err)
	}

	if err := groups.Validate(ctx); err != nil {
		return nil, fmt.Errorf("validating tunnel groups: %w", err)
	}

	return &groups, nil
}

type secretBearerSource struct {
	informer  cache.SharedIndexInformer
	namespace string
	name      string
	key       string
	hashed    bool
}

func newSecretBearerSource(ctx context.Context, namespace, name, key string, hashed bool) (*secretBearerSource, error) {
	source := &secretBearerSource{namespace: namespace, name: name, key: key, hashed: hashed}
	config, err := k8sConfig()
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	factory := informers.NewFilteredSharedInformerFactory(client, 0, namespace, nil)

	source.informer = factory.Core().V1().Secrets().Informer()
	source.informer.AddEventHandler(TypedEventHandler[v1.Secret]{
		logger: slog.With("resource", "secret"),
	})

	factory.Start(ctx.Done())
	// wait for initial list to complete and watchers to begin before proceeding
	factory.WaitForCacheSync(ctx.Done())

	return source, nil
}

// GetCredential returns a bearer credential
// HandleBearerSource expects all tokens to have been hashed with SHA256
func (s *secretBearerSource) GetCredential() ([]byte, error) {
	name := cache.ObjectName{
		Namespace: s.namespace,
		Name:      s.name,
	}

	obj, exists, err := s.informer.GetStore().Get(name)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("secret not found: %v", name)
	}

	secret, ok := obj.(v1.Secret)
	if !ok {
		return nil, fmt.Errorf("secret unexpected type: %T", obj)
	}

	token, ok := secret.Data[s.key]
	if !ok {
		return nil, errors.New("secret data empty")
	}

	if s.hashed {
		dst := make([]byte, hex.DecodedLen(len(token)))
		_, err := hex.Decode(dst, token)
		return dst, err
	}

	return token, nil
}

func k8sConfig() (*rest.Config, error) {
	if cfg := os.Getenv("KUBECONFIG"); cfg != "" {
		return clientcmd.BuildConfigFromFlags("", cfg)
	}

	return rest.InClusterConfig()
}

type TypedEventHandler[T any] struct {
	logger     *slog.Logger
	AddFunc    func(T)
	UpdateFunc func(T, T)
	DeleteFunc func(T)
}

// OnAdd calls AddFunc if it's not nil.
func (t TypedEventHandler[T]) OnAdd(obj interface{}, isInInitialList bool) {
	t.logger.Debug("Resource added")
	if t.AddFunc != nil {
		t.AddFunc(obj.(T))
	}
}

// OnUpdate calls UpdateFunc if it's not nil.
func (t TypedEventHandler[T]) OnUpdate(oldObj, newObj interface{}) {
	t.logger.Debug("Resource updated")
	if t.UpdateFunc != nil {
		t.UpdateFunc(oldObj.(T), newObj.(T))
	}
}

// OnDelete calls DeleteFunc if it's not nil.
func (t TypedEventHandler[T]) OnDelete(obj interface{}) {
	t.logger.Debug("Resource deleted")
	if t.DeleteFunc != nil {
		t.DeleteFunc(obj.(T))
	}
}
