package evidence

import (
	"testing"
)

// Store

func TestStore_InitialState(t *testing.T) {
	s := NewStore()

	b, ok := s.Get()
	if ok {
		t.Fatal("expected Get to return false on new store")
	}
	if b != nil {
		t.Fatal("expected nil bundle on new store")
	}
	if s.HasEvidence() {
		t.Fatal("expected HasEvidence false on new store")
	}
}

func TestStore_SetAndGet(t *testing.T) {
	s := NewStore()
	b := testBundle()

	s.Set(b)

	got, ok := s.Get()
	if !ok {
		t.Fatal("expected Get to return true after Set")
	}
	if got != b {
		t.Fatal("expected same bundle pointer")
	}
}

func TestStore_HasEvidence(t *testing.T) {
	s := NewStore()

	// no bundle
	if s.HasEvidence() {
		t.Fatal("expected false with no bundle")
	}

	// bundle with no files
	s.Set(&Bundle{Files: map[string]*EvidenceFile{}})
	if s.HasEvidence() {
		t.Fatal("expected false with empty Files")
	}

	// bundle with files
	s.Set(testBundle())
	if !s.HasEvidence() {
		t.Fatal("expected true with populated Files")
	}
}

func TestStore_File(t *testing.T) {
	s := NewStore()

	// empty store
	f, ok := s.File("any")
	if ok || f != nil {
		t.Fatal("expected nil/false on empty store")
	}

	s.Set(testBundle())
	f, ok = s.File("source/sbom/spdx.json")
	if !ok || f == nil {
		t.Fatal("expected file to be found")
	}

	f, ok = s.File("nonexistent")
	if ok || f != nil {
		t.Fatal("expected nil/false for missing file")
	}
}

func TestStore_FileRef(t *testing.T) {
	s := NewStore()

	// empty store
	ref, ok := s.FileRef("any")
	if ok || ref != nil {
		t.Fatal("expected nil/false on empty store")
	}

	s.Set(testBundle())
	ref, ok = s.FileRef("source/sbom/spdx.json")
	if !ok || ref == nil {
		t.Fatal("expected ref to be found")
	}

	ref, ok = s.FileRef("nonexistent")
	if ok || ref != nil {
		t.Fatal("expected nil/false for missing ref")
	}
}

func TestStore_Replace(t *testing.T) {
	s := NewStore()
	b1 := testBundle()
	b2 := &Bundle{
		Release:   &ReleaseManifest{ReleaseID: "rel-new", Version: "2.0.0"},
		FileIndex: map[string]*EvidenceFileRef{},
		Files:     map[string]*EvidenceFile{},
	}

	s.Set(b1)
	s.Set(b2) // replace

	got, ok := s.Get()
	if !ok {
		t.Fatal("expected true")
	}
	if got.Release.ReleaseID != "rel-new" {
		t.Fatalf("ReleaseID = %q, want rel-new", got.Release.ReleaseID)
	}
}
