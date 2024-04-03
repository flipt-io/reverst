package config

import "log/slog"

type Level slog.Level

func (l Level) String() string {
	return slog.Level(l).String()
}

func (l *Level) Set(v string) error {
	level := slog.Level(*l)
	if err := level.UnmarshalText([]byte(v)); err != nil {
		return err
	}

	*l = Level(level)
	return nil
}

// TunnelGroups is a configuration file format for defining the
// tunnels groups served by an instance of then reverst tunnel server
type TunnelGroups struct {
	Groups map[string]TunneGroup `json:"groups,omitempty" yaml:"groups,omitempty"`
}

type TunneGroup struct {
	Hosts []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`
}
