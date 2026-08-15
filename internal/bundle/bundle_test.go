package bundle

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/mmr"
	"github.com/DevGurav/hark/internal/signer"
)

// write builds a small bundle and returns its path. sealed=false leaves it
// without a footer, standing in for a run that was killed.
func write(t *testing.T, sealed bool, key *signer.Key) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run.hark")

	w, err := Create(path, Header{
		RunID:     "01TESTTESTTESTTESTTESTTEST",
		CreatedAt: time.Now().UnixNano(),
		Recorder:  "hark test",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Append(logfmt.KindRunStart, 0, logfmt.RunStart{RunID: "01TEST", WorkingDir: "/work"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(logfmt.KindEgressAttempt, 10, logfmt.EgressAttempt{Host: "evil.example", Port: 443}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(logfmt.KindEgressDecision, 11, logfmt.EgressDecision{
		Host: "evil.example", Allowed: false, Rule: "allow_hosts", Reason: "not allowed",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(logfmt.KindRunEnd, 20, logfmt.RunEnd{ExitCode: 1, Reason: "policy-abort"}); err != nil {
		t.Fatal(err)
	}

	if sealed {
		if _, err := w.Seal(key, time.Now().UnixNano(), "", 0); err != nil {
			t.Fatal(err)
		}
	} else if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSealedBundleVerifies(t *testing.T) {
	res, err := Verify(write(t, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSealed {
		t.Fatalf("status %s: %s", res.Status, res.Problem)
	}
	if res.LeafCount != 4 {
		t.Fatalf("expected 4 events, got %d", res.LeafCount)
	}
	if res.KindCounts[logfmt.KindEgressDecision] != 1 {
		t.Fatal("the egress decision was not counted")
	}
}

func TestSignedBundleVerifies(t *testing.T) {
	key, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(write(t, true, key))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSealed {
		t.Fatalf("status %s: %s", res.Status, res.Problem)
	}
	if !res.Signed || !res.SignatureOK {
		t.Fatal("a signed bundle did not report a valid signature")
	}
}

// An unsealed bundle is a legitimate outcome, not a failure. Everything written
// before the kill still has to verify.
func TestUnsealedBundleKeepsItsPrefix(t *testing.T) {
	res, err := Verify(write(t, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusTruncated {
		t.Fatalf("expected truncated, got %s", res.Status)
	}
	if res.LeafCount != 4 {
		t.Fatalf("expected the 4 written events to survive, got %d", res.LeafCount)
	}
}

func TestVerifyDetectsPayloadTampering(t *testing.T) {
	path := write(t, true, nil)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the egress decision's payload. Locating it by content
	// keeps the test honest about what was changed.
	idx := indexOf(raw, []byte("evil.example"))
	if idx < 0 {
		t.Fatal("could not locate the payload to tamper with")
	}
	raw[idx] = 'E'
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusBroken {
		t.Fatalf("tampering went undetected: status %s", res.Status)
	}
	if res.FirstBadSeq < 0 {
		t.Fatal("verifier did not report where the fault was")
	}
}

// Truncating mid-frame must be reported as truncation, not corruption: the
// distinction is what tells an operator "your process was killed" apart from
// "someone edited this file".
func TestVerifyHandlesMidFrameTruncation(t *testing.T) {
	path := write(t, true, nil)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw[:len(raw)-40], 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusTruncated {
		t.Fatalf("expected truncated, got %s (%s)", res.Status, res.Problem)
	}
}

func TestVerifyRejectsForeignFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not.hark")
	if err := os.WriteFile(path, []byte("this is not a bundle at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path); err == nil {
		t.Fatal("verifier accepted a file that is not a bundle")
	}
}

func TestInclusionProofAgainstSealedRoot(t *testing.T) {
	path := write(t, true, nil)

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}

	for seq := uint64(0); seq < res.LeafCount; seq++ {
		p, leaf, root, err := Prove(path, seq)
		if err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
		if root != res.Root {
			t.Fatalf("seq %d: proof root disagrees with the verified root", seq)
		}
		if !mmr.Verify(root, leaf, p) {
			t.Fatalf("seq %d: inclusion proof did not verify", seq)
		}
	}
}

func TestProveUnknownSeq(t *testing.T) {
	if _, _, _, err := Prove(write(t, true, nil), 99); err == nil {
		t.Fatal("expected an error for an event that does not exist")
	}
}

func TestCreateRefusesToOverwrite(t *testing.T) {
	path := write(t, true, nil)
	if _, err := Create(path, Header{RunID: "x"}); err == nil {
		t.Fatal("Create overwrote an existing bundle")
	}
}

func TestAppendAfterSealFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.hark")
	w, err := Create(path, Header{RunID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Seal(nil, time.Now().UnixNano(), "", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(logfmt.KindRunEnd, 0, logfmt.RunEnd{}); err == nil {
		t.Fatal("append succeeded after seal")
	}
}

func indexOf(haystack, needle []byte) int {
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
