// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"net"
	"time"

	"github.com/Sneakers-PAM/sneakers-release/migrate/internal/wait"
	"github.com/spf13/cobra"
)

type waitOptions struct {
	dns   string
	tcp   []string
	every time.Duration
}

// WaitCmd blocks until a DNS name resolves and a list of TCP targets accept
// a connection, so an init container can gate a step on its dependencies.
func WaitCmd(lg logFn) *cobra.Command {
	o := &waitOptions{}
	cmd := &cobra.Command{
		Use:   "wait",
		Short: "Block until a DNS name resolves and TCP targets accept a connection",
		Long: `wait resolves --dns first, retrying every --every until it resolves, then
dials each --tcp target in the order given, retrying each the same way until
it connects. It retries forever: the caller owns the time bound (an init
container's own timeout), never this command. Exits 0 once every target has
answered.`,
		Args: cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if o.dns == "" {
				return usage("--dns is required")
			}
			if len(o.tcp) == 0 {
				return usage("at least one --tcp is required")
			}
			for _, t := range o.tcp {
				if _, _, err := net.SplitHostPort(t); err != nil {
					return usage("--tcp %q: %v", t, err)
				}
			}
			if o.every <= 0 {
				return usage("--every must be positive")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			cfg := wait.Config{DNS: o.dns, TCP: o.tcp, Every: o.every}
			return wait.Run(ctxOf(cmd), cfg, net.DefaultResolver, lg(cmd))
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.dns, "dns", "d", "", "DNS name to resolve before dialing any --tcp target")
	f.StringArrayVarP(&o.tcp, "tcp", "t", nil, "host:port target to dial, in order (repeatable)")
	f.DurationVarP(&o.every, "every", "e", 2*time.Second, "how long to wait between retries of a target that isn't answering yet")
	return cmd
}
