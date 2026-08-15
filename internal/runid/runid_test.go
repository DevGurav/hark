package runid

import (
	"sort"
	"testing"
	"time"
)

func TestLengthAndAlphabet(t *testing.T) {
	for i := 0; i < 200; i++ {
		id, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != Length {
			t.Fatalf("id %q has length %d, want %d", id, len(id), Length)
		}
		if err := Valid(id); err != nil {
			t.Fatalf("generated id %q failed its own validation: %v", id, err)
		}
	}
}

// The reason for choosing ULID over UUIDv4: ids issued later must sort after ids
// issued earlier, so a directory listing is chronological.
func TestLexicographicOrderFollowsTime(t *testing.T) {
	base := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

	var ids []string
	for i := 0; i < 50; i++ {
		id, err := at(base.Add(time.Duration(i) * time.Second))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	sorted := make([]string, len(ids))
	copy(sorted, ids)
	sort.Strings(sorted)

	for i := range ids {
		if ids[i] != sorted[i] {
			t.Fatal("ids do not sort into the order they were created in")
		}
	}
}

func TestSameMillisecondStillUnique(t *testing.T) {
	fixed := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	seen := make(map[string]bool)
	for i := 0; i < 5000; i++ {
		id, err := at(fixed)
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatal("two ids collided within the same millisecond")
		}
		seen[id] = true
	}
}

// Crockford base32 deliberately omits I, L, O and U so ids stay unambiguous when
// read aloud or retyped.
func TestAmbiguousCharactersExcluded(t *testing.T) {
	for _, c := range "ILOU" {
		for i := 0; i < len(encoding); i++ {
			if rune(encoding[i]) == c {
				t.Fatalf("alphabet contains the ambiguous character %q", c)
			}
		}
	}
}

func TestValidRejectsMalformed(t *testing.T) {
	if Valid("TOOSHORT") == nil {
		t.Fatal("a short string validated")
	}
	if Valid("IIIIIIIIIIIIIIIIIIIIIIIIII") == nil {
		t.Fatal("a string of excluded characters validated")
	}
}
