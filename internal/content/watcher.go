// internal/content/watcher.go
//
// Watcher polls SSM for content bundle hash changes and hot-swaps
// the active content in the Manager when a new bundle is detected.
//
// Usage in main.go:
//
//	watcher := content.NewWatcher(content.WatcherOptions{
//	    Logger:       L,
//	    Loader:       contentLoader,
//	    Manager:      contentMgr,
//	    PollInterval: 30 * time.Second,
//	    OnSwap: func(hash, version string) {
//	        m.SetContentBundle(hash)
//	        m.SetContentSource(string(content.SourceS3))
//	        m.SetContentLoadedTimestamp(time.Now())
//	    },
//	})
//	go watcher.Run(ctx)
package content

import (
	"context"
	"math"
	"time"

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

// WatcherOptions configures the content bundle watcher.
type WatcherOptions struct {
	Logger       log.Logger
	Loader       *Loader
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
}

// Watcher polls SSM for content bundle hash changes and hot-swaps
// the active content when a new bundle is detected.
type Watcher struct {
	loader     *Loader
	manager    *Manager
	logger     log.Logger
	interval   time.Duration
	validation ValidationOptions
	onSwap     func(hash, version string)

	// hash tracking for change detection and cleanup
	currentHash  string // what's currently serving
	previousHash string // one-deep warm fallback on disk

	// stats for shutdown log and future metrics
	consecutiveErrs int
	pollCount       int64
	swapCount       int64
}

// NewWatcher creates a content watcher. Call Run to start the poll loop.
func NewWatcher(opts WatcherOptions) *Watcher {
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
		currentHash = snap.Meta.SHA256
	}

	validation := DefaultValidationOptions()
	if opts.Validation != nil {
		validation = *opts.Validation
	}

	return &Watcher{
		loader:      opts.Loader,
		manager:     opts.Manager,
		logger:      opts.Logger,
		interval:    interval,
		validation:  validation,
		onSwap:      opts.OnSwap,
		currentHash: currentHash,
	}
}

// Run starts the poll loop. Blocks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	w.logger.Info(ctx, "content watcher starting",
		"poll_interval", w.interval.String(),
		"current_hash", w.currentHash,
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
		}
	}
}

// checkOnce performs a single poll-compare-swap cycle.
// Returns what happened so Run can adjust timing.
func (w *Watcher) checkOnce(ctx context.Context) pollResult {
	w.pollCount++

	// poll SSM for the current bundle hash
	hash, err := w.loader.FetchCurrentBundleHash(ctx)
	if err != nil {
		w.logger.Error(ctx, err, "content watcher: SSM poll failed")
		return pollSSMError
	}

	// no change - most common path
	if hash == w.currentHash {
		return pollNoChange
	}

	// new hash detected
	w.logger.Info(ctx, "content watcher: new bundle hash detected",
		"old_hash", w.currentHash,
		"new_hash", hash,
	)

	// download, verify, extract, build snapshot
	snap, err := w.loader.LoadHash(ctx, hash)
	if err != nil {
		w.logger.Error(ctx, err, "content watcher: failed to load bundle",
			"hash", hash,
		)
		return pollLoadError
	}

	// validate the new bundle before swapping
	if err := ValidateSnapshot(snap, w.validation); err != nil {
		w.logger.Error(ctx, err, "content watcher: new bundle failed validation, keeping current content",
			"rejected_hash", hash,
			"current_hash", w.currentHash,
		)
		// clean up the rejected bundle's extracted directory
		if cleanErr := w.loader.CleanupHash(hash); cleanErr != nil {
			w.logger.Warn(ctx, "content watcher: failed to cleanup rejected bundle directory",
				"hash", hash,
				"error", cleanErr,
			)
		}
		return pollValidationError
	}

	// atomic swap into manager
	w.manager.Set(*snap)
	w.swapCount++

	oldHash := w.currentHash
	version := w.manager.ContentVersion()

	w.logger.Info(ctx, "content watcher: bundle swapped",
		"old_hash", oldHash,
		"new_hash", hash,
		"version", version,
		"total_swaps", w.swapCount,
	)

	// cleanup n-2 directory - keep one previous as warm fallback on disk
	// first swap: previousHash is empty, nothing to clean
	// second swap: clean the original startup bundle
	if w.previousHash != "" {
		if err := w.loader.CleanupHash(w.previousHash); err != nil {
			w.logger.Warn(ctx, "content watcher: failed to cleanup old bundle directory",
				"hash", w.previousHash,
				"error", err,
			)
		}
	}
	w.previousHash = oldHash
	w.currentHash = hash

	// notify caller (metrics, etc.)
	if w.onSwap != nil {
		w.onSwap(hash, version)
	}

	return pollSwapped
}

// backoffDuration computes exponential backoff capped at maxBackoff.
func (w *Watcher) backoffDuration() time.Duration {
	mult := math.Pow(2, float64(w.consecutiveErrs))
	d := time.Duration(float64(w.interval) * mult)
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}
