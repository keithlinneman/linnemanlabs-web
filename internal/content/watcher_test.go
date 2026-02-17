package content

import (
	"context"
	"encoding/json"
	"errors"
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

	loader := &Loader{
		opts: LoaderOptions{
			Logger:    log.Nop(),
			SSMParam:  testSSMParam,
			S3Bucket:  testBucket,
			S3Prefix:  testS3Prefix,
			S3Client:  s3fake,
			SSMClient: ssmFake,
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

func TestNewWatcher_NilLogger_UsesNop(t *testing.T) {
	f := newWatcherFixture(t, "")
	w := f.newWatcher(func(o *WatcherOptions) {
		o.Logger = nil
	})
	if w.logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestNewWatcher_DefaultValidation(t *testing.T) {
	f := newWatcherFixture(t, "")
	w := f.newWatcher()

	defaults := DefaultValidationOptions()
	if w.validation.MinFiles != defaults.MinFiles {
		t.Fatalf("MinFiles = %d, want %d", w.validation.MinFiles, defaults.MinFiles)
	}
}

func TestNewWatcher_CustomValidation(t *testing.T) {
	f := newWatcherFixture(t, "")
	custom := &ValidationOptions{MinFiles: 5, RequireProvenance: true}
	w := f.newWatcher(func(o *WatcherOptions) {
		o.Validation = custom
	})

	if w.validation.MinFiles != 5 {
		t.Fatalf("MinFiles = %d, want 5", w.validation.MinFiles)
	}
	if !w.validation.RequireProvenance {
		t.Fatal("RequireProvenance should be true")
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
	if len(f.swapCalls) != 0 {
		t.Fatalf("OnSwap called %d times, want 0", len(f.swapCalls))
	}
}

// checkOnce - SSM error

func TestCheckOnce_SSMError(t *testing.T) {
	f := newWatcherFixture(t, "initial")
	f.ssm.err = errors.New("SSM timeout")

	w := f.newWatcher()
	result := w.checkOnce(t.Context())
	if result != pollSSMError {
		t.Fatalf("result = %d, want pollSSMError", result)
	}
}

// checkOnce - load error

func TestCheckOnce_LoadError(t *testing.T) {
	bundleData, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleData)

	// point SSM at a hash that doesn't exist in S3
	newHash := "0000000000000000000000000000000000000000000000000000000000000000"
	f.ssm.value = &newHash

	w := f.newWatcher()
	result := w.checkOnce(t.Context())
	if result != pollLoadError {
		t.Fatalf("result = %d, want pollLoadError", result)
	}

	// manager should still serve old content
	snap, _ := f.mgr.Get()
	if snap.Meta.SHA256 != hashA {
		t.Fatalf("manager hash = %q, want %q (old content preserved)", snap.Meta.SHA256, hashA)
	}
}

// checkOnce - successful swap

func TestCheckOnce_Swap(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	_, hashB := storeBundle(t, f, map[string]string{
		"index.html": "<html>updated</html>",
	})
	f.ssm.value = &hashB

	w := f.newWatcher()
	result := w.checkOnce(t.Context())
	if result != pollSwapped {
		t.Fatalf("result = %d, want pollSwapped", result)
	}

	// manager should serve new content
	snap, ok := f.mgr.Get()
	if !ok {
		t.Fatal("manager should have content")
	}
	if snap.Meta.SHA256 != hashB {
		t.Fatalf("manager hash = %q, want %q", snap.Meta.SHA256, hashB)
	}

	// OnSwap callback should have fired
	if len(f.swapCalls) != 1 {
		t.Fatalf("OnSwap called %d times, want 1", len(f.swapCalls))
	}
	if f.swapCalls[0].hash != hashB {
		t.Fatalf("OnSwap hash = %q, want %q", f.swapCalls[0].hash, hashB)
	}

	// watcher state should be updated
	if w.currentHash != hashB {
		t.Fatalf("currentHash = %q, want %q", w.currentHash, hashB)
	}
	if w.swapCount != 1 {
		t.Fatalf("swapCount = %d, want 1", w.swapCount)
	}
}

// checkOnce - validation error

func TestCheckOnce_ValidationError_NoIndexHTML(t *testing.T) {
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

func TestCheckOnce_MultipleSwaps(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	w := f.newWatcher()

	// swap A → B
	_, hashB := storeBundle(t, f, map[string]string{
		"index.html": "<html>B</html>",
	})
	f.ssm.value = &hashB
	result := w.checkOnce(t.Context())
	if result != pollSwapped {
		t.Fatalf("first swap: result = %d, want pollSwapped", result)
	}

	// swap B → C
	_, hashC := storeBundle(t, f, map[string]string{
		"index.html": "<html>C</html>",
	})
	f.ssm.value = &hashC
	result = w.checkOnce(t.Context())
	if result != pollSwapped {
		t.Fatalf("second swap: result = %d, want pollSwapped", result)
	}

	if w.swapCount != 2 {
		t.Fatalf("swapCount = %d, want 2", w.swapCount)
	}
	if w.currentHash != hashC {
		t.Fatalf("currentHash = %q, want %q", w.currentHash, hashC)
	}
	if len(f.swapCalls) != 2 {
		t.Fatalf("OnSwap called %d times, want 2", len(f.swapCalls))
	}
}

// checkOnce - nil OnSwap is safe

func TestCheckOnce_NilOnSwap(t *testing.T) {
	bundleDataA, hashA := buildContentBundle(t)
	f := newWatcherFixture(t, hashA)
	f.seedManager(t, hashA, bundleDataA)

	_, hashB := storeBundle(t, f, map[string]string{
		"index.html": "<html>B</html>",
	})
	f.ssm.value = &hashB

	w := f.newWatcher(func(o *WatcherOptions) {
		o.OnSwap = nil // should not panic
	})
	result := w.checkOnce(t.Context())
	if result != pollSwapped {
		t.Fatalf("result = %d, want pollSwapped", result)
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

// truncHash

func TestTruncHash_Short(t *testing.T) {
	if got := truncHash("abc"); got != "abc" {
		t.Fatalf("truncHash(%q) = %q", "abc", got)
	}
}

func TestTruncHash_Exact12(t *testing.T) {
	if got := truncHash("123456789012"); got != "123456789012" {
		t.Fatalf("truncHash = %q", got)
	}
}

func TestTruncHash_Long(t *testing.T) {
	long := "abcdef1234567890abcdef"
	if got := truncHash(long); got != "abcdef123456" {
		t.Fatalf("truncHash = %q, want %q", got, "abcdef123456")
	}
}

func TestTruncHash_Empty(t *testing.T) {
	if got := truncHash(""); got != "" {
		t.Fatalf("truncHash(%q) = %q", "", got)
	}
}
