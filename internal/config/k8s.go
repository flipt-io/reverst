package config

import (
	"context"
	"crypto/sha256"
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
	"k8s.io/client-go/informers/core"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type k8sSource struct {
	logger  *slog.Logger
	factory informers.SharedInformerFactory
}

func newK8sSource(ctx context.Context) (*k8sSource, error) {
	config, err := k8sConfig()
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return newK8sSourceForClientset(ctx, client), nil
}

func newK8sSourceForClientset(ctx context.Context, clientset kubernetes.Interface) *k8sSource {
	src := &k8sSource{
		logger:  slog.With("component", "k8s_source"),
		factory: informers.NewSharedInformerFactory(clientset, 0),
	}

	src.logger.Debug("Starting Informer Factory")

	src.factory.Start(ctx.Done())

	return src
}

func (s *k8sSource) watchConfigMap(ctx context.Context, ch chan<- *TunnelGroups, namespace, name, key string) error {
	informer := core.New(s.factory, namespace, func(lo *metav1.ListOptions) {
		lo.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	}).V1().ConfigMaps().Informer()

	informer.AddEventHandler(TypedEventHandler[*v1.ConfigMap]{
		logger: slog.With("resource", "configmap"),
		AddFunc: func(cm *v1.ConfigMap) {
			tg, err := buildTunnelGroupsFromConfigMap(ctx, cm, key)
			if err != nil {
				s.logger.Error("Converting ConfigMap into tunnel groups", "error", err)
				return
			}

			ch <- tg
		},
		UpdateFunc: func(_, cm *v1.ConfigMap) {
			tg, err := buildTunnelGroupsFromConfigMap(ctx, cm, key)
			if err != nil {
				s.logger.Error("Converting ConfigMap into tunnel groups", "error", err)
				return
			}

			ch <- tg
		},
	})

	s.logger.Debug("Starting ConfigMap Watcher")

	go informer.Run(ctx.Done())

	// wait for initial list to complete and watchers to begin before proceeding
	s.logger.Debug("Waiting for Cache Sync")
	s.factory.WaitForCacheSync(ctx.Done())

	return nil
}

func buildTunnelGroupsFromConfigMap(ctx context.Context, cfg *v1.ConfigMap, key string) (*TunnelGroups, error) {
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

func (s *k8sSource) newSecretBearerSource(ctx context.Context, namespace, name, key string, hashed bool) (*secretBearerSource, error) {
	source := &secretBearerSource{namespace: namespace, name: name, key: key, hashed: hashed}

	source.informer = core.New(s.factory, namespace, nil).V1().Secrets().Informer()
	source.informer.AddEventHandler(TypedEventHandler[*v1.Secret]{
		logger: s.logger.With("resource", "secret"),
	})

	s.logger.Debug("Starting secret watcher")
	go source.informer.Run(ctx.Done())

	s.logger.Debug("Waiting for cache sync")
	// wait for initial list to complete and watchers to begin before proceeding
	for !source.informer.HasSynced() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		s.factory.WaitForCacheSync(ctx.Done())
	}

	s.logger.Debug("Finished waiting for sync")

	return source, nil
}

// GetCredential returns a bearer credential
// HandleBearerSource expects all tokens to have been hashed with SHA256
func (s *secretBearerSource) GetCredential() ([]byte, error) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.namespace,
			Name:      s.name,
		},
	}

	obj, exists, err := s.informer.GetStore().Get(secret)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("secret not found: %s/%s", secret.ObjectMeta.GetNamespace(), secret.ObjectMeta.GetName())
	}

	secret, ok := obj.(*v1.Secret)
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

	dst := sha256.Sum256(token)
	return dst[:], nil
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
	if t.logger != nil {
		t.logger.Debug("Resource added")
	}

	if t.AddFunc != nil {
		t.AddFunc(obj.(T))
	}
}

// OnUpdate calls UpdateFunc if it's not nil.
func (t TypedEventHandler[T]) OnUpdate(oldObj, newObj interface{}) {
	if t.logger != nil {
		t.logger.Debug("Resource updated")
	}

	if t.UpdateFunc != nil {
		var oldT T
		if oldObj != nil {
			oldT = oldObj.(T)
		}

		var newT T
		if newObj != nil {
			newT = newObj.(T)
		}

		t.UpdateFunc(oldT, newT)
	}
}

// OnDelete calls DeleteFunc if it's not nil.
func (t TypedEventHandler[T]) OnDelete(obj interface{}) {
	if t.logger != nil {
		t.logger.Debug("Resource deleted")
	}

	if t.DeleteFunc != nil {
		t.DeleteFunc(obj.(T))
	}
}
