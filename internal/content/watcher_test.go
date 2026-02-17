package content

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// watcher test helpers

// watcherFixture holds all the pieces needed to test the watcher.
type watcherFixture struct {
	s3     *fakeS3
	ssm    *fakeSSM
	mgr    *Manager
	loader *Loader

	// track OnSwap calls
	swapCalls []swapRecord
}

type swapRecord struct {
	hash    string
	version string
}

// newWatcherFixture creates a full test harness with fakes wired in.
// The SSM starts returning initialHash so the startup content is "known".
func newWatcherFixture(t *testing.T, initialHash string) *watcherFixture {
	t.Helper()

	s3fake := newFakeS3()
	ssmFake := ssmWithValue(initialHash)

	extractDir := t.TempDir()

	loader := &Loader{
		opts: LoaderOptions{
			Logger:     log.Nop(),
			SSMParam:   testSSMParam,
			S3Bucket:   testBucket,
			S3Prefix:   testS3Prefix,
			ExtractDir: extractDir,
			S3Client:   s3fake,
			SSMClient:  ssmFake,
		},
		s3Client:  s3fake,
		ssmClient: ssmFake,
		logger:    log.Nop(),
	}

	mgr := NewManager()

	return &watcherFixture{
		s3:     s3fake,
		ssm:    ssmFake,
		mgr:    mgr,
		loader: loader,
	}
}

// seedManager loads a bundle into the manager so it has a known current hash.
func (f *watcherFixture) seedManager(t *testing.T, hash string, data []byte) {
	t.Helper()
	putBundle(f.s3, hash, data)
	snap, err := f.loader.LoadHash(t.Context(), hash)
	if err != nil {
		t.Fatalf("seedManager LoadHash: %v", err)
	}
	f.mgr.Set(*snap)
}

// newWatcher creates a Watcher from the fixture with optional overrides.
func (f *watcherFixture) newWatcher(opts ...func(*WatcherOptions)) *Watcher {
	wopts := WatcherOptions{
		Logger:       log.Nop(),
		Loader:       f.loader,
		Manager:      f.mgr,
		PollInterval: time.Second, // won't tick in checkOnce tests
		OnSwap: func(hash, version string) {
			f.swapCalls = append(f.swapCalls, swapRecord{hash, version})
		},
	}
	for _, fn := range opts {
		fn(&wopts)
	}
	return NewWatcher(wopts)
}

// storeBundle creates a valid content bundle, stores it in fakeS3, and returns
// the raw bytes and hash.
func storeBundle(t *testing.T, f *watcherFixture, files map[string]string) ([]byte, string) {
	t.Helper()
	data := makeTarGz(t, files)
	hash := cryptoutil.SHA256Hex(data)
	putBundle(f.s3, hash, data)
	return data, hash
}

// backoffDuration

func TestBackoffDuration_Progression(t *testing.T) {
	w := &Watcher{interval: 30 * time.Second}

	tests := []struct {
		consecutiveErrs int
		wantMin         time.Duration
		wantMax         time.Duration
	}{
		{1, 60 * time.Second, 60 * time.Second},   // 2x
		{2, 120 * time.Second, 120 * time.Second}, // 4x
		{3, 240 * time.Second, 240 * time.Second}, // 8x
		{4, 5 * time.Minute, 5 * time.Minute},     // 16x=480s, capped at 300s
		{10, 5 * time.Minute, 5 * time.Minute},    // way over cap
	}

	for _, tt := range tests {
		w.consecutiveErrs = tt.consecutiveErrs
		got := w.backoffDuration()
		if got < tt.wantMin || got > tt.wantMax {
			t.Fatalf("consecutiveErrs=%d: backoff=%v, want [%v, %v]",
				tt.consecutiveErrs, got, tt.wantMin, tt.wantMax)
		}
	}
}

func TestBackoffDuration_ZeroErrors(t *testing.T) {
	w := &Watcher{interval: 30 * time.Second, consecutiveErrs: 0}
	got := w.backoffDuration()
	// 2^0 * 30s = 30s
	if got != 30*time.Second {
		t.Fatalf("backoff = %v, want 30s", got)
	}
}

// NewWatcher

func TestNewWatcher_DefaultInterval(t *testing.T) {
	f := newWatcherFixture(t, "")
	w := f.newWatcher(func(o *WatcherOptions) {
		o.PollInterval = 0 // should default
	})
	if w.interval != DefaultPollInterval {
		t.Fatalf("interval = %v, want %v", w.interval, DefaultPollInterval)
	}
}

func TestNewWatcher_CustomInterval(t *testing.T) {
	f := newWatcherFixture(t, "")
	w := f.newWatcher(func(o *WatcherOptions) {
		o.PollInterval = 10 * time.Second
	})
	if w.interval != 10*time.Second {
		t.Fatalf("interval = %v, want 10s", w.interval)
	}
}

func TestNewWatcher_NegativeInterval_UsesDefault(t *testing.T) {
	f := newWatcherFixture(t, "")
	w := f.newWatcher(func(o *WatcherOptions) {
		o.PollInterval = -5 * time.Second
	})
	if w.interval != DefaultPollInterval {
		t.Fatalf("interval = %v, want %v", w.interval, DefaultPollInterval)
	}
}

func TestNewWatcher_SeedsCurrentHash(t *testing.T) {
	bundleData, bundleHash := buildContentBundle(t)
	f := newWatcherFixture(t, bundleHash)
	f.seedManager(t, bundleHash, bundleData)

	w := f.newWatcher()
	if w.currentHash != bundleHash {
		t.Fatalf("currentHash = %q, want %q", w.currentHash, bundleHash)
	}
}

func TestNewWatcher_EmptyManager_EmptyHash(t *testing.T) {
	f := newWatcherFixture(t, "")
	w := f.newWatcher()
	if w.currentHash != "" {
		t.Fatalf("currentHash = %q, want empty", w.currentHash)
	}
}

func TestNewWatcher_NilLogger(t *testing.T) {
	f := newWatcherFixture(t, "")
	w := f.newWatcher(func(o *WatcherOptions) {
		o.Logger = nil
	})
	if w.logger == nil {
		t.Fatal("logger should default to nop, not nil")
	}
}

func TestNewWatcher_DefaultValidationOptions(t *testing.T) {
	f := newWatcherFixture(t, "")
	w := f.newWatcher()
	defaults := DefaultValidationOptions()
	if w.validation != defaults {
		t.Fatalf("validation = %+v, want %+v", w.validation, defaults)
	}
}

func TestNewWatcher_CustomValidationOptions(t *testing.T) {
	f := newWatcherFixture(t, "")
	custom := ValidationOptions{MinFiles: 10, RequireProvenance: true}
	w := f.newWatcher(func(o *WatcherOptions) {
		o.Validation = &custom
	})
	if w.validation != custom {
		t.Fatalf("validation = %+v, want %+v", w.validation, custom)
	}
}

// checkOnce - no change

func TestCheckOnce_NoChange(t *testing.T) {
	bundleData, bundleHash := buildContentBundle(t)
	f := newWatcherFixture(t, bundleHash)
	f.seedManager(t, bundleHash, bundleData)

	w := f.newWatcher()

	result := w.checkOnce(t.Context())
	if result != pollNoChange {
		t.Fatalf("result = %d, want pollNoChange", result)
	}
	if w.pollCount != 1 {
		t.Fatalf("pollCount = %d, want 1", w.pollCount)
	}
	if w.swapCount != 0 {
		t.Fatalf("swapCount = %d, want 0", w.swapCount)
	}
}

// checkOnce - successful swap

func TestCheckOnce_Swap(t *testing.T) {
	// start with bundle A
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	// store bundle B in S3
	_, hashB := storeBundle(t, f, map[string]string{
		"index.html": "<html>new content</html>",
	})

	// SSM now returns hash B
	f.ssm.value = &hashB

	w := f.newWatcher()

	result := w.checkOnce(t.Context())
	if result != pollSwapped {
		t.Fatalf("result = %d, want pollSwapped", result)
	}
	if w.swapCount != 1 {
		t.Fatalf("swapCount = %d, want 1", w.swapCount)
	}
	if w.currentHash != hashB {
		t.Fatalf("currentHash = %q, want %q", w.currentHash, hashB)
	}
	if w.previousHash != hashA {
		t.Fatalf("previousHash = %q, want %q", w.previousHash, hashA)
	}

	// manager should serve new content
	snap, ok := f.mgr.Get()
	if !ok {
		t.Fatal("manager should have content")
	}
	if snap.Meta.SHA256 != hashB {
		t.Fatalf("manager hash = %q, want %q", snap.Meta.SHA256, hashB)
	}
}

func TestCheckOnce_Swap_OnSwapCalled(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	_, hashB := storeBundle(t, f, map[string]string{
		"index.html": "<html>v2</html>",
	})
	f.ssm.value = &hashB

	w := f.newWatcher()
	w.checkOnce(t.Context())

	if len(f.swapCalls) != 1 {
		t.Fatalf("OnSwap called %d times, want 1", len(f.swapCalls))
	}
	if f.swapCalls[0].hash != hashB {
		t.Fatalf("OnSwap hash = %q, want %q", f.swapCalls[0].hash, hashB)
	}
}

func TestCheckOnce_Swap_NilOnSwap_NoPanic(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	_, hashB := storeBundle(t, f, map[string]string{
		"index.html": "<html>v2</html>",
	})
	f.ssm.value = &hashB

	w := f.newWatcher(func(o *WatcherOptions) {
		o.OnSwap = nil
	})

	// should not panic
	result := w.checkOnce(t.Context())
	if result != pollSwapped {
		t.Fatalf("result = %d, want pollSwapped", result)
	}
}

// checkOnce - SSM error

func TestCheckOnce_SSMError(t *testing.T) {
	f := newWatcherFixture(t, "initial")
	f.ssm.err = errors.New("SSM throttle")

	w := f.newWatcher()
	result := w.checkOnce(t.Context())
	if result != pollSSMError {
		t.Fatalf("result = %d, want pollSSMError", result)
	}
	if w.swapCount != 0 {
		t.Fatalf("swapCount = %d, want 0", w.swapCount)
	}
}

// checkOnce - load error (S3 fails)

func TestCheckOnce_LoadError(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	// SSM returns new hash, but S3 doesn't have it
	newHash := "aaaa000000000000000000000000000000000000000000000000000000000000"
	f.ssm.value = &newHash

	w := f.newWatcher()
	result := w.checkOnce(t.Context())
	if result != pollLoadError {
		t.Fatalf("result = %d, want pollLoadError", result)
	}

	// manager should still serve old content
	snap, ok := f.mgr.Get()
	if !ok {
		t.Fatal("manager should still have content")
	}
	if snap.Meta.SHA256 != hashA {
		t.Fatalf("manager hash = %q, want %q (old content preserved)", snap.Meta.SHA256, hashA)
	}

	// currentHash should NOT be updated
	if w.currentHash != hashA {
		t.Fatalf("currentHash = %q, want %q (unchanged on failure)", w.currentHash, hashA)
	}
}

// checkOnce - validation error

func TestCheckOnce_ValidationError_MissingIndex(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	// new bundle has NO index.html - will fail validation
	_, hashB := storeBundle(t, f, map[string]string{
		"about.html": "<html>no index</html>",
	})
	f.ssm.value = &hashB

	w := f.newWatcher()
	result := w.checkOnce(t.Context())
	if result != pollValidationError {
		t.Fatalf("result = %d, want pollValidationError", result)
	}

	// manager should still serve old content
	snap, _ := f.mgr.Get()
	if snap.Meta.SHA256 != hashA {
		t.Fatalf("manager hash = %q, want %q (old content preserved)", snap.Meta.SHA256, hashA)
	}

	// currentHash should NOT be updated - next poll will retry
	if w.currentHash != hashA {
		t.Fatalf("currentHash = %q, want %q (unchanged on validation failure)", w.currentHash, hashA)
	}

	// no swap callback
	if len(f.swapCalls) != 0 {
		t.Fatalf("OnSwap called %d times, want 0", len(f.swapCalls))
	}
}

func TestCheckOnce_ValidationError_CleansUpRejectedBundle(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	// new bundle will fail validation (no index.html)
	_, hashB := storeBundle(t, f, map[string]string{
		"about.html": "<html>rejected</html>",
	})
	f.ssm.value = &hashB

	w := f.newWatcher()
	w.checkOnce(t.Context())

	// the rejected bundle's directory should be cleaned up
	rejectedDir := filepath.Join(f.loader.opts.ExtractDir, hashB)
	if _, err := os.Stat(rejectedDir); !os.IsNotExist(err) {
		t.Fatal("rejected bundle directory should be cleaned up")
	}
}

func TestCheckOnce_ValidationError_ProvenanceHashMismatch(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	// bundle with provenance that has a mismatched content_hash
	prov, _ := json.Marshal(Provenance{
		Version:     "2.0.0",
		ContentHash: "wrong-hash-does-not-match-bundle",
		Summary:     ProvenanceSummary{TotalFiles: 1},
	})
	_, hashB := storeBundle(t, f, map[string]string{
		"index.html":      "<html>new</html>",
		"provenance.json": string(prov),
	})
	f.ssm.value = &hashB

	w := f.newWatcher()
	result := w.checkOnce(t.Context())
	if result != pollValidationError {
		t.Fatalf("result = %d, want pollValidationError", result)
	}
}

// checkOnce - n-2 cleanup lifecycle

func TestCheckOnce_Cleanup_FirstSwapNoCleanup(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	_, hashB := storeBundle(t, f, map[string]string{
		"index.html": "<html>B</html>",
	})
	f.ssm.value = &hashB

	w := f.newWatcher()

	// first swap: previousHash was empty, no cleanup should happen
	w.checkOnce(t.Context())

	// hashA directory should still exist (it's now "previous")
	dirA := filepath.Join(f.loader.opts.ExtractDir, hashA)
	if _, err := os.Stat(dirA); os.IsNotExist(err) {
		t.Fatal("hashA directory should still exist after first swap (it's the warm fallback)")
	}
}

func TestCheckOnce_Cleanup_SecondSwapCleansN2(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	// first swap: A → B
	_, hashB := storeBundle(t, f, map[string]string{
		"index.html": "<html>B</html>",
	})
	f.ssm.value = &hashB

	w := f.newWatcher()
	w.checkOnce(t.Context())

	// second swap: B → C
	_, hashC := storeBundle(t, f, map[string]string{
		"index.html": "<html>C</html>",
	})
	f.ssm.value = &hashC

	w.checkOnce(t.Context())

	// hashA (n-2) should be cleaned up
	dirA := filepath.Join(f.loader.opts.ExtractDir, hashA)
	if _, err := os.Stat(dirA); !os.IsNotExist(err) {
		t.Fatal("hashA directory (n-2) should be cleaned up after second swap")
	}

	// hashB (previous/n-1) should still exist as warm fallback
	dirB := filepath.Join(f.loader.opts.ExtractDir, hashB)
	if _, err := os.Stat(dirB); os.IsNotExist(err) {
		t.Fatal("hashB directory should still exist (warm fallback)")
	}

	// hashC (current) should exist
	dirC := filepath.Join(f.loader.opts.ExtractDir, hashC)
	if _, err := os.Stat(dirC); os.IsNotExist(err) {
		t.Fatal("hashC directory should exist (current)")
	}
}

// checkOnce - multiple polls, stats

func TestCheckOnce_PollCount_Increments(t *testing.T) {
	bundleData, bundleHash := buildContentBundle(t)
	f := newWatcherFixture(t, bundleHash)
	f.seedManager(t, bundleHash, bundleData)

	w := f.newWatcher()

	for i := 0; i < 5; i++ {
		w.checkOnce(t.Context())
	}
	if w.pollCount != 5 {
		t.Fatalf("pollCount = %d, want 5", w.pollCount)
	}
	if w.swapCount != 0 {
		t.Fatalf("swapCount = %d, want 0 (no changes)", w.swapCount)
	}
}

// Run - integration

func TestRun_StopsOnContextCancel(t *testing.T) {
	f := newWatcherFixture(t, "initial")

	w := f.newWatcher(func(o *WatcherOptions) {
		o.PollInterval = 10 * time.Millisecond
	})

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- w.Run(ctx)
	}()

	// let it tick a few times
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}

func TestRun_DetectsChange(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	// store bundle B
	_, hashB := storeBundle(t, f, map[string]string{
		"index.html": "<html>updated</html>",
	})

	var swapCount atomic.Int32

	w := NewWatcher(WatcherOptions{
		Logger:       log.Nop(),
		Loader:       f.loader,
		Manager:      f.mgr,
		PollInterval: 10 * time.Millisecond,
		OnSwap: func(hash, version string) {
			swapCount.Add(1)
		},
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go w.Run(ctx)

	// wait a couple ticks for it to see "no change"
	time.Sleep(30 * time.Millisecond)

	// update SSM to point at bundle B
	f.ssm.value = &hashB

	// wait for the watcher to detect and swap
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("watcher did not swap within deadline")
		default:
			if swapCount.Load() > 0 {
				snap, ok := f.mgr.Get()
				if !ok {
					t.Fatal("manager should have content")
				}
				if snap.Meta.SHA256 != hashB {
					t.Fatalf("manager hash = %q, want %q", snap.Meta.SHA256, hashB)
				}
				return // success
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestRun_BacksOffOnSSMError_ThenRecovers(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	w := f.newWatcher(func(o *WatcherOptions) {
		o.PollInterval = 10 * time.Millisecond
	})

	// start with SSM errors
	f.ssm.err = errors.New("SSM unavailable")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go w.Run(ctx)

	// let it accumulate some errors
	time.Sleep(50 * time.Millisecond)

	if w.consecutiveErrs == 0 {
		t.Fatal("expected consecutive errors to accumulate")
	}

	// fix SSM - point at existing bundle (no change)
	f.ssm.err = nil
	f.ssm.value = &hashA

	// wait for recovery
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("watcher did not recover within deadline")
		default:
			if w.consecutiveErrs == 0 {
				return // recovered
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
