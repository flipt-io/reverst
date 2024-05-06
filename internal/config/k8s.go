package config

import (
	"context"
	"fmt"
	"log/slog"

	"go.flipt.io/reverst/internal/k8s"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
)

func watchK8sConfigMap(ctx context.Context, ch chan<- *TunnelGroups, namespace, name, key string, watch bool) error {
	watcher, err := k8s.New(namespace, name)
	if err != nil {
		return err
	}

	// get initial configmap before we return to ensure
	// we fail fast if we can't get at-least one
	cfg, err := watcher.Get(ctx)
	if err != nil {
		return err
	}

	groups, err := buildTunnelGroupsFromConfigMap(cfg, key)
	if err != nil {
		return err
	}

	ch <- groups

	if !watch {
		return nil
	}

	slog.Info("Starting ConfigMap watcher", "namespace", namespace, "name", name)

	cfgs := make(chan v1.ConfigMap)
	watcher.StartWatching(ctx, cfgs)

	go func() {
		defer close(ch)
		defer close(cfgs)

		for {
			select {
			case <-ctx.Done():
				return
			case cfg, ok := <-cfgs:
				if !ok {
					return
				}

				groups, err := buildTunnelGroupsFromConfigMap(cfg, key)
				if err != nil {
					slog.Error("Building tunnel groups from ConfigMap", "error", err, "namespace", namespace, "name", name)
					continue
				}

				ch <- groups
			}
		}
	}()

	return nil
}

func buildTunnelGroupsFromConfigMap(cfg v1.ConfigMap, key string) (*TunnelGroups, error) {
	raw, ok := cfg.Data[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in ConfigMap", key)
	}

	var groups TunnelGroups
	if err := yaml.Unmarshal([]byte(raw), &groups); err != nil {
		return nil, fmt.Errorf("decoding tunnel groups: %w", err)
	}

	if err := groups.Validate(); err != nil {
		return nil, fmt.Errorf("validating tunnel groups: %w", err)
	}

	return &groups, nil
}
