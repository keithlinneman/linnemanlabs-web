package content

import (
	"fmt"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// NewManager / Get initial state

func TestManager_InitialState(t *testing.T) {
	m := NewManager()

	snap, ok := m.Get()
	if ok {
		t.Fatal("expected Get to return false on new manager")
	}
	if snap != nil {
		t.Fatal("expected nil snapshot on new manager")
	}
}

// Set / Get

func TestManager_SetAndGet(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	m.Set(Snapshot{
		FS: fs,
		Meta: Meta{
			Hash:          "abc123",
			HashAlgorithm: "sha384",
			Source:        SourceS3,
			Version:       "1.0.0",
		},
	})

	snap, ok := m.Get()
	if !ok {
		t.Fatal("expected Get to return true after Set")
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.Meta.Hash != "abc123" {
		t.Fatalf("Hash = %q, want abc123", snap.Meta.Hash)
	}
	if snap.Meta.HashAlgorithm != "sha384" {
		t.Fatalf("HashAlgorithm = %q, want sha384", snap.Meta.HashAlgorithm)
	}
	if snap.Meta.Version != "1.0.0" {
		t.Fatalf("Version = %q, want 1.0.0", snap.Meta.Version)
	}
}

func TestManager_Get_RequiresFS(t *testing.T) {
	m := NewManager()

	// Set snapshot with nil FS
	m.Set(Snapshot{
		Meta: Meta{Hash: "abc123"},
	})

	snap, ok := m.Get()
	if ok {
		t.Fatal("expected Get to return false when FS is nil")
	}
	// snap is non-nil (pointer exists) but ok is false
	_ = snap
}

func TestManager_Set_CopiesSnapshot(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	original := Snapshot{
		FS:   fs,
		Meta: Meta{Hash: "abc123", Version: "1.0.0"},
	}
	m.Set(original)

	// mutate the original - should not affect stored snapshot
	original.Meta.Hash = "mutated"

	snap, ok := m.Get()
	if !ok {
		t.Fatal("expected true")
	}
	if snap.Meta.Hash != "abc123" {
		t.Fatalf("Hash = %q, want abc123 (should be a copy)", snap.Meta.Hash)
	}
}

func TestManager_Set_SetsLoadedAt(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	before := time.Now().UTC().Add(-time.Second)
	m.Set(Snapshot{
		FS:   fs,
		Meta: Meta{Hash: "abc"},
	})
	after := time.Now().UTC().Add(time.Second)

	snap, _ := m.Get()
	if snap.LoadedAt.Before(before) || snap.LoadedAt.After(after) {
		t.Fatalf("LoadedAt = %v, expected between %v and %v", snap.LoadedAt, before, after)
	}
}

func TestManager_Set_PreservesExistingLoadedAt(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	explicit := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	m.Set(Snapshot{
		FS:       fs,
		Meta:     Meta{Hash: "abc"},
		LoadedAt: explicit,
	})

	snap, _ := m.Get()
	if !snap.LoadedAt.Equal(explicit) {
		t.Fatalf("LoadedAt = %v, want %v (should preserve explicit value)", snap.LoadedAt, explicit)
	}
}

func TestManager_Set_Replace(t *testing.T) {
	m := NewManager()
	fs1 := fstest.MapFS{"v1.html": &fstest.MapFile{Data: []byte("v1")}}
	fs2 := fstest.MapFS{"v2.html": &fstest.MapFile{Data: []byte("v2")}}

	m.Set(Snapshot{FS: fs1, Meta: Meta{Version: "1.0"}})
	m.Set(Snapshot{FS: fs2, Meta: Meta{Version: "2.0"}})

	snap, ok := m.Get()
	if !ok {
		t.Fatal("expected true")
	}
	if snap.Meta.Version != "2.0" {
		t.Fatalf("Version = %q, want 2.0", snap.Meta.Version)
	}
}

// Rollback

func TestManager_Rollback_NoPrevious(t *testing.T) {
	m := NewManager()
	if m.Rollback() {
		t.Fatal("expected Rollback to return false with no previous snapshot")
	}
}

func TestManager_Rollback_RestoresPrevious(t *testing.T) {
	m := NewManager()
	fs1 := fstest.MapFS{"v1.html": &fstest.MapFile{Data: []byte("v1")}}
	fs2 := fstest.MapFS{"v2.html": &fstest.MapFile{Data: []byte("v2")}}

	m.Set(Snapshot{FS: fs1, Meta: Meta{Version: "1.0", Hash: "hash1"}})
	m.Set(Snapshot{FS: fs2, Meta: Meta{Version: "2.0", Hash: "hash2"}})

	if !m.Rollback() {
		t.Fatal("expected Rollback to return true")
	}

	snap, ok := m.Get()
	if !ok {
		t.Fatal("expected true after rollback")
	}
	if snap.Meta.Version != "1.0" {
		t.Fatalf("Version = %q, want 1.0 after rollback", snap.Meta.Version)
	}
}

// ContentVersion

func TestManager_ContentVersion_Empty(t *testing.T) {
	m := NewManager()
	if v := m.ContentVersion(); v != "" {
		t.Fatalf("ContentVersion = %q, want empty on new manager", v)
	}
}

func TestManager_ContentVersion_FromMeta(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	m.Set(Snapshot{
		FS:   fs,
		Meta: Meta{Version: "meta-1.0"},
	})

	if v := m.ContentVersion(); v != "meta-1.0" {
		t.Fatalf("ContentVersion = %q, want meta-1.0", v)
	}
}

func TestManager_ContentVersion_PrefersProvenance(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	m.Set(Snapshot{
		FS:         fs,
		Meta:       Meta{Version: "meta-1.0"},
		Provenance: &Provenance{Version: "prov-2.0"},
	})

	if v := m.ContentVersion(); v != "prov-2.0" {
		t.Fatalf("ContentVersion = %q, want prov-2.0 (provenance preferred)", v)
	}
}

func TestManager_ContentVersion_FallsBackToMeta(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	// Provenance exists but has empty version
	m.Set(Snapshot{
		FS:         fs,
		Meta:       Meta{Version: "meta-1.0"},
		Provenance: &Provenance{Version: ""},
	})

	if v := m.ContentVersion(); v != "meta-1.0" {
		t.Fatalf("ContentVersion = %q, want meta-1.0 (fallback when provenance version empty)", v)
	}
}

// ContentHash

func TestManager_ContentHash_Empty(t *testing.T) {
	m := NewManager()
	if h := m.ContentHash(); h != "" {
		t.Fatalf("ContentHash = %q, want empty on new manager", h)
	}
}

func TestManager_ContentHash_FromMeta(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	m.Set(Snapshot{
		FS:   fs,
		Meta: Meta{Hash: "deadbeef1234"},
	})

	if h := m.ContentHash(); h != "deadbeef1234" {
		t.Fatalf("ContentHash = %q, want deadbeef1234", h)
	}
}

func TestManager_ContentHash_AlwaysReturnsMeta(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	// ContentHash always returns Meta.Hash (the verified download hash),
	// regardless of what provenance contains
	m.Set(Snapshot{
		FS:         fs,
		Meta:       Meta{Hash: "meta_hash"},
		Provenance: &Provenance{ContentHash: "prov_hash"},
	})

	if h := m.ContentHash(); h != "meta_hash" {
		t.Fatalf("ContentHash = %q, want meta_hash (always uses verified Meta.Hash)", h)
	}
}

// Provenance

func TestManager_Provenance_Nil(t *testing.T) {
	m := NewManager()
	if p := m.Provenance(); p != nil {
		t.Fatal("expected nil provenance on new manager")
	}
}

func TestManager_Provenance_NilWhenNoProvenance(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	m.Set(Snapshot{FS: fs, Meta: Meta{Hash: "abc"}})

	if p := m.Provenance(); p != nil {
		t.Fatal("expected nil provenance when snapshot has none")
	}
}

func TestManager_Provenance_Present(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}

	prov := &Provenance{
		Version:     "1.2.3",
		ContentHash: "abc123",
		Source: ProvenanceSource{
			Repository:  "github.com/test/repo",
			CommitShort: "abc1234",
		},
		Summary: ProvenanceSummary{
			TotalFiles: 42,
			TotalSize:  1024000,
		},
	}

	m.Set(Snapshot{FS: fs, Meta: Meta{Hash: "abc"}, Provenance: prov})

	got := m.Provenance()
	if got == nil {
		t.Fatal("expected non-nil provenance")
	}
	if got.Version != "1.2.3" {
		t.Fatalf("Version = %q", got.Version)
	}
	if got.Summary.TotalFiles != 42 {
		t.Fatalf("TotalFiles = %d", got.Summary.TotalFiles)
	}
}

// ReadyErr (from probe.go)

func TestManager_ReadyErr_NoSnapshot(t *testing.T) {
	m := NewManager()
	if err := m.ReadyErr(); err == nil {
		t.Fatal("expected error when no snapshot loaded")
	}
}

func TestManager_ReadyErr_WithSnapshot(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}
	m.Set(Snapshot{FS: fs, Meta: Meta{Hash: "abc"}})

	if err := m.ReadyErr(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManager_ReadyErr_NilFS(t *testing.T) {
	m := NewManager()
	m.Set(Snapshot{Meta: Meta{Hash: "abc"}}) // nil FS

	if err := m.ReadyErr(); err == nil {
		t.Fatal("expected error when FS is nil")
	}
}

func TestManager_Source_Empty(t *testing.T) {
	m := NewManager()
	if s := m.Source(); s != SourceUnknown {
		t.Fatalf("Source = %q, want %q", s, SourceUnknown)
	}
}

func TestManager_Source_ReturnsActive(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}
	m.Set(Snapshot{FS: fs, Meta: Meta{Source: SourceS3}})

	if s := m.Source(); s != SourceS3 {
		t.Fatalf("Source = %q, want %q", s, SourceS3)
	}
}

func TestManager_LoadedAt_Empty(t *testing.T) {
	m := NewManager()
	if got := m.LoadedAt(); !got.IsZero() {
		t.Fatalf("LoadedAt = %v, want zero", got)
	}
}

func TestManager_LoadedAt_ReturnsActive(t *testing.T) {
	m := NewManager()
	fs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>")}}
	m.Set(Snapshot{FS: fs, Meta: Meta{Source: SourceS3}})

	if got := m.LoadedAt(); got.IsZero() {
		t.Fatal("LoadedAt should be set after Set()")
	}
}

// ConcurrentAccess — validated by `go test -race`

func TestManager_ConcurrentAccess(t *testing.T) {
	const (
		numWriters   = 10
		numReaders   = 20
		numRollbacks = 3
		writeIters   = 100
		readIters    = 100
		rollbackIters = 50
	)

	// Pre-build distinct snapshots so each writer has unique data.
	snapshots := make([]Snapshot, numWriters)
	for i := range snapshots {
		snapshots[i] = Snapshot{
			FS: fstest.MapFS{
				"index.html": &fstest.MapFile{Data: []byte(fmt.Sprintf("<html>%d</html>", i))},
			},
			Meta: Meta{
				Hash:    fmt.Sprintf("hash-%d", i),
				Version: fmt.Sprintf("v%d", i),
				Source:  SourceS3,
			},
		}
	}

	m := NewManager()
	// Seed with snapshots[0] so Get() returns valid data from the start.
	m.Set(snapshots[0])

	start := make(chan struct{})
	var wg sync.WaitGroup

	// Writers
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for i := 0; i < writeIters; i++ {
				m.Set(snapshots[id])
			}
		}(w)
	}

	// Readers
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < readIters; i++ {
				m.Get()
				m.ContentVersion()
				m.ContentHash()
				m.Source()
				m.LoadedAt()
				m.Provenance()
				m.ReadyErr()
			}
		}()
	}

	// Rollback goroutines
	for rb := 0; rb < numRollbacks; rb++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < rollbackIters; i++ {
				m.Rollback()
			}
		}()
	}

	close(start)
	wg.Wait()

	// After all goroutines finish, Get() should return a valid snapshot.
	snap, ok := m.Get()
	if !ok {
		t.Fatal("expected valid snapshot after concurrent access")
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot after concurrent access")
	}
}
