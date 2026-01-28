package healthhttp

import (
	"context"
	"database/sql"
	"time"
)

type StaticChecker struct {
	// extend this later with flags or funcs
}

type AppChecker struct {
	DB *sql.DB
	// maybe later: Redis, queue, cache, etc.
}

func (StaticChecker) Healthy(ctx context.Context) bool { return true }
func (StaticChecker) Ready(ctx context.Context) bool   { return true }

func (c *AppChecker) Healthy(ctx context.Context) bool {
	// cheap / fast checks: maybe always true, or something simple.
	return true
}

func (c *AppChecker) Ready(ctx context.Context) bool {
	if c.DB == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	if err := c.DB.PingContext(ctx); err != nil {
		return false
	}
	return true
}
