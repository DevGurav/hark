package logfmt

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/DevGurav/hark/internal/hashchain"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello")

	next, err := WriteFrame(&buf, KindRunStart, 0, 1234, hashchain.Zero, payload)
	if err != nil {
		t.Fatal(err)
	}

	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != KindRunStart || f.Seq != 0 || f.MonoNanos != 1234 {
		t.Fatalf("header fields did not survive the round trip: %+v", f)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Fatal("payload did not survive the round trip")
	}
	if f.Chain != next {
		t.Fatal("reader computed a different chain value than the writer")
	}
	if err := f.Validate(hashchain.Zero); err != nil {
		t.Fatalf("a freshly written frame failed validation: %v", err)
	}
}

func TestEmptyPayloadRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if _, err := WriteFrame(&buf, KindRunEnd, 0, 0, hashchain.Zero, nil); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Payload) != 0 {
		t.Fatalf("expected an empty payload, got %d bytes", len(f.Payload))
	}
	if err := f.Validate(hashchain.Zero); err != nil {
		t.Fatal(err)
	}
}

// A payload edited on disk must fail against its stored leaf hash. This is the
// check that separates "the file changed" from "the file was reordered".
func TestValidateDetectsPayloadEdit(t *testing.T) {
	var buf bytes.Buffer
	if _, err := WriteFrame(&buf, KindClockRead, 3, 0, hashchain.Zero, []byte("original")); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	raw[frameHeaderSize] ^= 0x01 // first payload byte

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Validate(hashchain.Zero); err == nil {
		t.Fatal("an edited payload passed validation")
	}
}

func TestValidateDetectsSplice(t *testing.T) {
	var buf bytes.Buffer
	if _, err := WriteFrame(&buf, KindClockRead, 3, 0, hashchain.Zero, []byte("x")); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}

	var wrong hashchain.Hash
	wrong[0] = 0xAA
	if err := f.Validate(wrong); err == nil {
		t.Fatal("a frame validated against the wrong predecessor")
	}
}

func TestFooterSentinel(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFooterSentinel(&buf); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, ErrFooter) {
		t.Fatalf("expected ErrFooter, got %v", err)
	}
}

// A run killed mid-write leaves a partial frame. The reader must say so
// specifically, because the caller keeps the verified prefix in that case.
func TestTruncatedFrameIsDistinguishable(t *testing.T) {
	var buf bytes.Buffer
	if _, err := WriteFrame(&buf, KindRunStart, 0, 0, hashchain.Zero, []byte("abcdefgh")); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()

	if _, err := ReadFrame(bytes.NewReader(raw[:len(raw)-5])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF for a truncated frame, got %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF at a clean end, got %v", err)
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	// Claim a payload larger than the cap without providing one; the reader must
	// refuse rather than try to allocate it.
	raw := []byte{0x7F, 0xFF, 0xFF, 0xFF}
	if _, err := ReadFrame(bytes.NewReader(raw)); err == nil {
		t.Fatal("reader accepted an oversized length")
	}
}

// Canonical encoding is what makes leaf hashes comparable across machines. Maps
// are the case that would otherwise vary, since Go randomises iteration order.
func TestCanonicalEncodingIsStable(t *testing.T) {
	v := EnvSnapshot{Vars: map[string]string{
		"ZED": "1", "ALPHA": "2", "MIKE": "3", "BRAVO": "4", "TANGO": "5",
	}}

	first, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		again, err := Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("canonical encoding of a map varied between calls")
		}
	}
}

func TestKindValidity(t *testing.T) {
	if !KindEgressDecision.Valid() {
		t.Fatal("a known kind reported itself invalid")
	}
	if Kind(200).Valid() {
		t.Fatal("an unknown kind reported itself valid")
	}
	if Kind(200).String() != "Unknown" {
		t.Fatal("unexpected name for an unknown kind")
	}
}
