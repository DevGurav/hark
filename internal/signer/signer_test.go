package signer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DevGurav/hark/internal/hashchain"
)

func testRoot(b byte) hashchain.Hash {
	var h hashchain.Hash
	h[0] = b
	return h
}

func TestSignAndVerify(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	sth := k.Sign("run-1", 42, testRoot(7), time.Now().UnixNano())
	if err := sth.Verify(); err != nil {
		t.Fatalf("a freshly signed tree head failed to verify: %v", err)
	}
}

// Every field in the signing input must actually be covered. If any of these
// pass, an attacker could move a valid signature onto a different claim.
func TestSignatureCoversEveryField(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	base := k.Sign("run-1", 42, testRoot(7), 1000)

	t.Run("root", func(t *testing.T) {
		s := *base
		r := testRoot(8)
		s.Root = r[:]
		if s.Verify() == nil {
			t.Fatal("signature survived a changed root")
		}
	})
	t.Run("leaf count", func(t *testing.T) {
		s := *base
		s.LeafCount = 43
		if s.Verify() == nil {
			t.Fatal("signature survived a changed leaf count")
		}
	})
	t.Run("run id", func(t *testing.T) {
		s := *base
		s.RunID = "run-2"
		if s.Verify() == nil {
			t.Fatal("signature survived a changed run id")
		}
	})
	t.Run("timestamp", func(t *testing.T) {
		s := *base
		s.SignedAt = 1001
		if s.Verify() == nil {
			t.Fatal("signature survived a changed timestamp")
		}
	})
	t.Run("signature bytes", func(t *testing.T) {
		s := *base
		sig := make([]byte, len(base.Signature))
		copy(sig, base.Signature)
		sig[0] ^= 0x01
		s.Signature = sig
		if s.Verify() == nil {
			t.Fatal("a modified signature verified")
		}
	})
}

// Length prefixing exists so that two different (runID, leafCount) pairs cannot
// produce the same signing input by shifting the boundary between them.
func TestRunIDBoundaryIsUnambiguous(t *testing.T) {
	a := signingBytes("ab", 1, testRoot(1), 0)
	b := signingBytes("a", 1, testRoot(1), 0)
	if string(a) == string(b) {
		t.Fatal("two different run ids produced the same signing input")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	good := k.Sign("run", 1, testRoot(1), 0)

	var nilSTH *STH
	if nilSTH.Verify() == nil {
		t.Fatal("nil tree head verified")
	}

	short := *good
	short.PublicKey = []byte{1, 2, 3}
	if short.Verify() == nil {
		t.Fatal("a malformed public key verified")
	}

	badRoot := *good
	badRoot.Root = []byte{1}
	if badRoot.Verify() == nil {
		t.Fatal("a malformed root verified")
	}
}

// A signature made by one key must not verify under another. This is the
// property that a pinned key relies on.
func TestForeignKeyRejected(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	sth := a.Sign("run", 1, testRoot(1), 0)
	sth.PublicKey = b.Public()
	if sth.Verify() == nil {
		t.Fatal("a signature verified under a substituted public key")
	}
}

func TestKeyRoundTripsThroughDisk(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "hark.key")
	if err := k.Save(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	sth := loaded.Sign("run", 5, testRoot(3), 0)
	if err := sth.Verify(); err != nil {
		t.Fatal(err)
	}
	if string(loaded.Public()) != string(k.Public()) {
		t.Fatal("the loaded key has a different public half")
	}
}

func TestLoadRejectsNonKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.key")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("LoadKey accepted a file that is not a key")
	}
}
