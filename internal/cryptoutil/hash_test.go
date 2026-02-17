package cryptoutil

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// SHA256Hex

func TestSHA256Hex_KnownVector(t *testing.T) {
	// SHA-256 of empty string is a well-known constant
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

func TestSHA256Hex_DifferentInputs(t *testing.T) {
	a := SHA256Hex([]byte("input-a"))
	b := SHA256Hex([]byte("input-b"))
	if a == b {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestSHA256Hex_Deterministic(t *testing.T) {
	data := []byte("deterministic")
	a := SHA256Hex(data)
	b := SHA256Hex(data)
	if a != b {
		t.Fatal("same input should produce same hash")
	}
}

func TestSHA256Hex_LargeInput(t *testing.T) {
	data := make([]byte, 1<<20) // 1MB of zeros
	got := SHA256Hex(data)
	if len(got) != 64 {
		t.Fatalf("SHA256Hex length = %d, want 64", len(got))
	}
}

// HashEqual

func TestHashEqual_IdenticalStrings(t *testing.T) {
	h := SHA256Hex([]byte("test"))
	if !HashEqual(h, h) {
		t.Fatal("identical hashes should be equal")
	}
}

func TestHashEqual_SameValue(t *testing.T) {
	a := SHA256Hex([]byte("same"))
	b := SHA256Hex([]byte("same"))
	if !HashEqual(a, b) {
		t.Fatal("same-value hashes should be equal")
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

func TestHashEqual_OneEmpty(t *testing.T) {
	h := SHA256Hex([]byte("data"))
	if HashEqual(h, "") {
		t.Fatal("hash vs empty should not be equal")
	}
	if HashEqual("", h) {
		t.Fatal("empty vs hash should not be equal")
	}
}

func TestHashEqual_CaseSensitive(t *testing.T) {
	lower := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	upper := "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
	if HashEqual(lower, upper) {
		t.Fatal("HashEqual should be case-sensitive (constant-time byte compare)")
	}
}

func TestHashEqual_DifferentLengths(t *testing.T) {
	if HashEqual("abc", "abcd") {
		t.Fatal("different length strings should not be equal")
	}
}

func TestHashEqual_SubstringPrefix(t *testing.T) {
	full := SHA256Hex([]byte("test"))
	prefix := full[:32]
	if HashEqual(full, prefix) {
		t.Fatal("full hash should not equal its prefix")
	}
}

// Fuzz

func FuzzSHA256Hex(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("hello"))
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xfe, 0xfd})

	f.Fuzz(func(t *testing.T, data []byte) {
		result := SHA256Hex(data)

		// INVARIANT: always 64 hex characters
		if len(result) != 64 {
			t.Errorf("SHA256Hex length = %d, want 64", len(result))
		}

		// INVARIANT: always lowercase hex
		if result != strings.ToLower(result) {
			t.Errorf("SHA256Hex not lowercase: %q", result)
		}

		// INVARIANT: valid hex
		if _, err := hex.DecodeString(result); err != nil {
			t.Errorf("SHA256Hex not valid hex: %v", err)
		}

		// INVARIANT: deterministic
		if SHA256Hex(data) != result {
			t.Error("SHA256Hex not deterministic")
		}

		// INVARIANT: matches stdlib directly
		h := sha256.Sum256(data)
		want := hex.EncodeToString(h[:])
		if result != want {
			t.Errorf("SHA256Hex = %q, stdlib = %q", result, want)
		}
	})
}

func FuzzHashEqual(f *testing.F) {
	f.Add("abc", "abc")
	f.Add("abc", "def")
	f.Add("", "")
	f.Add("a", "")

	f.Fuzz(func(t *testing.T, a, b string) {
		got := HashEqual(a, b)
		want := a == b

		// INVARIANT: HashEqual must agree with plain equality
		if got != want {
			t.Errorf("HashEqual(%q, %q) = %v, want %v", a, b, got, want)
		}

		// INVARIANT: symmetric
		if HashEqual(a, b) != HashEqual(b, a) {
			t.Errorf("HashEqual not symmetric for %q, %q", a, b)
		}
	})
}
