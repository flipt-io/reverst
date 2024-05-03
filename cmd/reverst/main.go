package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"go.flipt.io/reverst/internal/config"
	"go.flipt.io/reverst/internal/server"
)

func main() {
	flags := ff.NewFlagSet("reverst")

	var conf config.Config
	if err := flags.AddStruct(&conf); err != nil {
		panic(err)
	}

	cmd := &ff.Command{
		Name:  "reverst",
		Usage: "reverst [FLAGS]",
		Flags: flags,
		Exec: func(ctx context.Context, args []string) error {
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.Level(conf.Level),
			})))

			if err := conf.Validate(); err != nil {
				return err
			}

			groups, err := conf.TunnelGroups()
			if err != nil {
				return err
			}

			groupsChan := make(chan *config.TunnelGroups, 1)
			groupsChan <- groups

			if conf.WatchTunnelGroups {
				watcher, err := fsnotify.NewWatcher()
				if err != nil {
					return err
				}
				defer watcher.Close()

				go func() {
					defer close(groupsChan)

					for {
						select {
						case event, ok := <-watcher.Events:
							if !ok {
								return
							}

							if !event.Has(fsnotify.Write) {
								continue
							}

							groups, err := conf.TunnelGroups()
							if err != nil {
								slog.Error("reading tunnel groups: %w", err)
								continue
							}

							groupsChan <- groups
						case err, ok := <-watcher.Errors:
							if !ok {
								return
							}

							slog.Error("watching tunnel groups", "error", err)
						}
					}
				}()

				if err := watcher.Add(conf.TunnelGroupsPath); err != nil {
					return err
				}
			}

			server, err := server.New(conf, groupsChan)
			if err != nil {
				return err
			}

			return server.ListenAndServe(ctx)
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
	}()

	if err := cmd.ParseAndRun(ctx, os.Args[1:],
		ff.WithEnvVarPrefix("REVERST"),
	); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return
		}

		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Command(cmd))
		if !errors.Is(err, ff.ErrHelp) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}

		os.Exit(1)
	}
}
