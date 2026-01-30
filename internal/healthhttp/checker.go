package healthhttp

import (
	"context"
)

type StaticChecker struct {
	// extend later
}

type AppChecker struct {
	// maybe later redis/queue/cache/etc
}

func (StaticChecker) Healthy(ctx context.Context) bool { return true }
func (StaticChecker) Ready(ctx context.Context) bool   { return true }

func (c *AppChecker) Healthy(ctx context.Context) bool {
	// always true for now
	return true
}

func (c *AppChecker) Ready(ctx context.Context) bool {
	// always true for now
	return true
}
