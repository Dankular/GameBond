//go:build !windows

package main

import (
	"context"

	"gamebond.local/nativeedge/client"
)

func startDriverHealth(ctx context.Context, c *client.Client, adapterIDs []string) {}
