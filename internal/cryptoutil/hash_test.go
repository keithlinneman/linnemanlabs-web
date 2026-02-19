package cryptoutil

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
)

// SHA256Hex

func TestSHA256Hex_KnownVector(t *testing.T) {
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	got := SHA256Hex([]byte{})
	if got != want {
		t.Fatalf("SHA256Hex(empty) = %q, want %q", got, want)
	}
}

func TestSHA256Hex_HelloWorld(t *testing.T) {
	data := []byte("hello world")
	h := sha256.Sum256(data)
	want := hex.EncodeToString(h[:])
	got := SHA256Hex(data)
	if got != want {
		t.Fatalf("SHA256Hex = %q, want %q", got, want)
	}
}

func TestSHA256Hex_Length(t *testing.T) {
	got := SHA256Hex([]byte("anything"))
	if len(got) != 64 {
		t.Fatalf("SHA256Hex length = %d, want 64", len(got))
	}
}

func TestSHA256Hex_Lowercase(t *testing.T) {
	got := SHA256Hex([]byte("test"))
	if got != strings.ToLower(got) {
		t.Fatal("SHA256Hex should return lowercase hex")
	}
}

// SHA384Hex

func TestSHA384Hex_KnownVector(t *testing.T) {
	// SHA-384 of empty string
	want := "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
	got := SHA384Hex([]byte{})
	if got != want {
		t.Fatalf("SHA384Hex(empty) = %q, want %q", got, want)
	}
}

func TestSHA384Hex_HelloWorld(t *testing.T) {
	data := []byte("hello world")
	h := sha512.Sum384(data)
	want := hex.EncodeToString(h[:])
	got := SHA384Hex(data)
	if got != want {
		t.Fatalf("SHA384Hex = %q, want %q", got, want)
	}
}

func TestSHA384Hex_Length(t *testing.T) {
	got := SHA384Hex([]byte("anything"))
	if len(got) != 96 {
		t.Fatalf("SHA384Hex length = %d, want 96", len(got))
	}
}

func TestSHA384Hex_Lowercase(t *testing.T) {
	got := SHA384Hex([]byte("test"))
	if got != strings.ToLower(got) {
		t.Fatal("SHA384Hex should return lowercase hex")
	}
}

func TestSHA384Hex_DifferentInputs(t *testing.T) {
	a := SHA384Hex([]byte("input-a"))
	b := SHA384Hex([]byte("input-b"))
	if a == b {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestSHA384Hex_Deterministic(t *testing.T) {
	data := []byte("deterministic")
	a := SHA384Hex(data)
	b := SHA384Hex(data)
	if a != b {
		t.Fatal("same input should produce same hash")
	}
}

func TestSHA384Hex_DifferentFromSHA256(t *testing.T) {
	data := []byte("test data")
	s256 := SHA256Hex(data)
	s384 := SHA384Hex(data)
	if s256 == s384 {
		t.Fatal("SHA256 and SHA384 should produce different outputs")
	}
	if len(s256) == len(s384) {
		t.Fatal("SHA256 (64 chars) and SHA384 (96 chars) should have different lengths")
	}
}

// HashEqual (unchanged tests)

func TestHashEqual_IdenticalStrings(t *testing.T) {
	h := SHA256Hex([]byte("test"))
	if !HashEqual(h, h) {
		t.Fatal("identical hashes should be equal")
	}
}

func TestHashEqual_SHA384(t *testing.T) {
	a := SHA384Hex([]byte("same"))
	b := SHA384Hex([]byte("same"))
	if !HashEqual(a, b) {
		t.Fatal("same-value SHA384 hashes should be equal")
	}
}

func TestHashEqual_SHA384_Different(t *testing.T) {
	a := SHA384Hex([]byte("one"))
	b := SHA384Hex([]byte("two"))
	if HashEqual(a, b) {
		t.Fatal("different SHA384 hashes should not be equal")
	}
}

func TestHashEqual_DifferentValues(t *testing.T) {
	a := SHA256Hex([]byte("one"))
	b := SHA256Hex([]byte("two"))
	if HashEqual(a, b) {
		t.Fatal("different hashes should not be equal")
	}
}

func TestHashEqual_EmptyStrings(t *testing.T) {
	if !HashEqual("", "") {
		t.Fatal("two empty strings should be equal")
	}
}
