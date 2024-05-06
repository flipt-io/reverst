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
	cfgs := make(chan v1.ConfigMap)

	if err := k8s.WatchConfigMap(ctx, cfgs, namespace, name); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case cfg := <-cfgs:
		groups, err := buildTunnelGroupsFromConfigMap(cfg, key)
		if err != nil {
			return err
		}

		ch <- groups
	}

	if !watch {
		close(cfgs)
		close(ch)
		return nil
	}

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
