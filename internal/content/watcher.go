// internal/content/watcher.go
//
// Watcher polls SSM for content bundle hash changes and hot-swaps
// the active content in the Manager when a new bundle is detected.
//
// Content bundles are extracted to in-memory filesystems (MemFS), so there
// are no disk directories to clean up. Old snapshots are garbage-collected
// when the atomic pointer in the Manager is swapped.
package content

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

const (
	// DefaultPollInterval is how often the watcher checks SSM for a new hash.
	DefaultPollInterval = 30 * time.Second

	// maxBackoff caps exponential backoff on consecutive SSM errors.
	maxBackoff = 5 * time.Minute
)

// pollResult describes what happened during a single poll cycle.
type pollResult int

const (
	pollNoChange        pollResult = iota // SSM hash matches current - nothing to do
	pollSwapped                           // new hash detected, bundle loaded and swapped
	pollSSMError                          // SSM fetch failed - caller should back off
	pollLoadError                         // SSM succeeded but download/extract/swap failed
	pollValidationError                   // bundle loaded but failed health checks
)

// BundleFetcher is the interface the Watcher needs from a Loader. Extracted to
// decouple the Watcher from the concrete *Loader type, enabling simpler test
// doubles and future alternative implementations (e.g. OCI-based fetching).
type BundleFetcher interface {
	FetchCurrentBundleHash(ctx context.Context) (algorithm string, hash string, err error)
	LoadHash(ctx context.Context, algorithm, hash string) (*Snapshot, error)
}

// WatcherMetrics is implemented by the metrics package to observe watcher behavior.
type WatcherMetrics interface {
	IncWatcherPolls()
	IncWatcherSwaps()
	IncWatcherError(errType string)
	ObserveBundleLoadDuration(seconds float64)
	SetWatcherLastSuccess(unixSeconds float64)
	SetWatcherStale(stale bool)
}

// WatcherOptions configures the content bundle watcher.
type WatcherOptions struct {
	Logger       log.Logger
	Loader       BundleFetcher
	Manager      *Manager
	PollInterval time.Duration

	// Validation configures health checks run against new bundles
	// before they are swapped into the manager. Zero value uses
	// DefaultValidationOptions().
	Validation *ValidationOptions

	// OnSwap is called after a successful content swap.
	// Use to update Prometheus metrics, trigger cache invalidation, etc.
	// Called synchronously on the poll goroutine.
	OnSwap func(hash, version string)

	// Metrics receives watcher observability signals (polls, swaps, errors, durations).
	Metrics WatcherMetrics

	// StaleThreshold is how long since the last successful SSM poll before
	// the watcher logs a staleness warning. Zero defaults to 30 minutes.
	StaleThreshold time.Duration
}

// Watcher polls for content changes and hot-swaps bundles into the manager.
type Watcher struct {
	loader     BundleFetcher
	manager    *Manager
	logger     log.Logger
	interval   time.Duration
	validation ValidationOptions
	onSwap     func(hash, version string)
	metrics    WatcherMetrics

	// hash tracking for change detection
	currentHash string

	// backoff state
	consecutiveErrs int

	// staleness tracking
	staleThreshold time.Duration
	lastSuccessAt  time.Time
	staleLogged    bool

	// stats for logging and future metrics
	pollCount int64
	swapCount int64
}

// NewWatcher creates a content watcher. Call Run to start the poll loop.
func NewWatcher(opts *WatcherOptions) *Watcher {
	if opts.Logger == nil {
		opts.Logger = log.Nop()
	}
	interval := opts.PollInterval
	if interval <= 0 {
		interval = DefaultPollInterval
	}

	// seed current hash from manager so first poll doesn't re-download
	// what was already loaded at startup
	currentHash := ""
	if snap, ok := opts.Manager.Get(); ok {
		currentHash = snap.Meta.Hash
	}

	validation := DefaultValidationOptions()
	if opts.Validation != nil {
		validation = *opts.Validation
	}

	staleThreshold := opts.StaleThreshold
	if staleThreshold <= 0 {
		staleThreshold = 30 * time.Minute
	}

	return &Watcher{
		loader:         opts.Loader,
		manager:        opts.Manager,
		logger:         opts.Logger,
		interval:       interval,
		validation:     validation,
		onSwap:         opts.OnSwap,
		metrics:        opts.Metrics,
		currentHash:    currentHash,
		staleThreshold: staleThreshold,
		lastSuccessAt:  time.Now(),
	}
}

// Run starts the poll loop. Blocks until ctx is cancelled.
// Intended to be launched as: go watcher.Run(ctx)
func (w *Watcher) Run(ctx context.Context) error {
	w.logger.Info(ctx, "content watcher starting",
		"poll_interval", w.interval.String(),
		"current_hash", truncHash(w.currentHash),
	)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info(ctx, "content watcher stopping",
				"reason", ctx.Err(),
				"polls", w.pollCount,
				"swaps", w.swapCount,
			)
			return ctx.Err()
		case <-ticker.C:
			result := w.checkOnce(ctx)

			if result == pollSSMError {
				w.consecutiveErrs++
				backoff := w.backoffDuration()
				w.logger.Warn(ctx, "content watcher: backing off",
					"consecutive_errors", w.consecutiveErrs,
					"next_poll_in", backoff.String(),
				)
				ticker.Reset(backoff)
			} else if w.consecutiveErrs > 0 {
				// recovered from error streak - resume normal cadence
				w.logger.Info(ctx, "content watcher: recovered, resuming normal interval",
					"had_consecutive_errors", w.consecutiveErrs,
				)
				w.consecutiveErrs = 0
				ticker.Reset(w.interval)
			}

			// staleness detection: emit structured error once on transition into stale state
			if result != pollSSMError {
				// non-SSM-error means lastSuccessAt was updated
				if w.staleLogged {
					w.logger.Info(ctx, "content watcher: staleness recovered")
					w.staleLogged = false
					if w.metrics != nil {
						w.metrics.SetWatcherStale(false)
					}
				}
			} else if time.Since(w.lastSuccessAt) > w.staleThreshold {
				if !w.staleLogged {
					w.logger.Error(ctx, fmt.Errorf("last successful SSM poll was %s ago", time.Since(w.lastSuccessAt).Truncate(time.Second)),
						"content watcher: content is stale, unable to verify freshness",
					)
					w.staleLogged = true
					if w.metrics != nil {
						w.metrics.SetWatcherStale(true)
					}
				}
			}
		}
	}
}

// checkOnce performs a single poll-compare-swap cycle.
// Returns what happened so Run can adjust timing.
func (w *Watcher) checkOnce(ctx context.Context) pollResult {
	w.pollCount++
	if w.metrics != nil {
		w.metrics.IncWatcherPolls()
	}

	// poll SSM for the current bundle hash
	algorithm, hash, err := w.loader.FetchCurrentBundleHash(ctx)
	if err != nil {
		w.logger.Error(ctx, err, "content watcher: SSM poll failed")
		if w.metrics != nil {
			w.metrics.IncWatcherError("ssm")
		}
		return pollSSMError
	}

	// SSM call succeeded - update last success time
	now := time.Now()
	w.lastSuccessAt = now
	if w.metrics != nil {
		w.metrics.SetWatcherLastSuccess(float64(now.Unix()))
	}

	// no change - most common path
	if cryptoutil.HashEqual(hash, w.currentHash) {
		return pollNoChange
	}

	// new hash detected
	w.logger.Info(ctx, "content watcher: new bundle hash detected",
		"old_hash", truncHash(w.currentHash),
		"new_hash", truncHash(hash),
	)

	// download, verify, extract to memory
	loadStart := time.Now()
	snap, err := w.loader.LoadHash(ctx, algorithm, hash)
	loadDur := time.Since(loadStart).Seconds()
	if w.metrics != nil {
		w.metrics.ObserveBundleLoadDuration(loadDur)
	}

	if err != nil {
		w.logger.Error(ctx, err, "content watcher: failed to load bundle",
			"hash", truncHash(hash),
		)
		if w.metrics != nil {
			w.metrics.IncWatcherError("load")
		}
		return pollLoadError
	}

	// validate the new bundle before swapping
	if err := ValidateSnapshot(snap, w.validation); err != nil {
		w.logger.Error(ctx, err, "content watcher: new bundle failed validation, keeping current content",
			"rejected_hash", truncHash(hash),
			"current_hash", truncHash(w.currentHash),
		)
		if w.metrics != nil {
			w.metrics.IncWatcherError("validation")
		}
		// no disk cleanup needed - MemFS is garbage collected
		return pollValidationError
	}

	// atomic swap into manager - old MemFS becomes garbage
	oldHash := w.currentHash
	w.manager.Set(*snap)
	w.swapCount++

	version := w.manager.ContentVersion()

	w.logger.Info(ctx, "content watcher: bundle swapped",
		"old_hash", truncHash(oldHash),
		"new_hash", truncHash(hash),
		"version", version,
		"total_swaps", w.swapCount,
	)

	w.currentHash = hash

	if w.metrics != nil {
		w.metrics.IncWatcherSwaps()
	}

	// notify caller (metrics, etc.)
	if w.onSwap != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					w.logger.Error(ctx, fmt.Errorf("OnSwap panic: %v", r),
						"content watcher: OnSwap callback panicked, continuing",
						"hash", truncHash(hash),
					)
				}
			}()
			w.onSwap(hash, version)
		}()
	}

	return pollSwapped
}

// backoffDuration computes exponential backoff capped at maxBackoff.
// consecutiveErrs=1 → 2x interval, =2 → 4x, =3 → 8x, etc.
func (w *Watcher) backoffDuration() time.Duration {
	mult := math.Pow(2, float64(w.consecutiveErrs))
	d := time.Duration(float64(w.interval) * mult)
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

// truncHash returns the first 12 characters of a hash for logging.
func truncHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
