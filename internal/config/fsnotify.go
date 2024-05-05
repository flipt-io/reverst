package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v2"
)

func watchFSNotify(ctx context.Context, ch chan<- *TunnelGroups, path string, watch bool) error {
	groups, err := buildTunnelGroupsAtPath(path)
	if err != nil {
		return err
	}

	// feed initial channel group
	ch <- groups

	if !watch {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	go func() {
		defer close(ch)

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				slog.Debug("Watcher event", "event", event)

				if !(event.Has(fsnotify.Remove)) {
					continue
				}

				groups, err := buildTunnelGroupsAtPath(path)
				if err != nil {
					slog.Error("reading tunnel groups: %w", err)
					continue
				}

				ch <- groups

				// remove and re-add as the file has been moved atomically
				watcher.Remove(event.Name)
				watcher.Add(path)

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}

				slog.Error("watching tunnel groups", "error", err)
			}
		}
	}()

	if err := watcher.Add(path); err != nil {
		return err
	}

	return nil
}

func buildTunnelGroupsAtPath(path string) (*TunnelGroups, error) {
	fi, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading tunnel groups: %w", err)
	}

	defer fi.Close()

	var groups TunnelGroups
	if err := yaml.NewDecoder(fi).Decode(&groups); err != nil {
		return nil, fmt.Errorf("decoding tunnel groups: %w", err)
	}

	if err := groups.Validate(); err != nil {
		return nil, fmt.Errorf("validating tunnel groups: %w", err)
	}

	return &groups, nil
}
