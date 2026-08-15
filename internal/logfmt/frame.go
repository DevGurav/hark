package logfmt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/DevGurav/hark/internal/hashchain"
)

// Frame wire layout, all integers big-endian:
//
//	 0  u32  payload length
//	 4  u8   kind
//	 5  u64  seq
//	13  u64  monotonic nanoseconds since run start
//	21  32B  chain value of the preceding frame
//	53  ...  canonical CBOR payload
//	..  32B  leaf hash of this frame
//
// The leaf hash is stored rather than recomputed on the fly so a reader can
// detect a corrupt payload precisely: if the recomputed leaf disagrees with the
// stored one, this frame is damaged; if the leaf agrees but the chain does not,
// the damage is a reordering or a splice. Those are different failures and a
// verifier should be able to tell them apart.
const (
	frameHeaderSize = 4 + 1 + 8 + 8 + hashchain.Size
	frameTrailer    = hashchain.Size

	// MaxPayload bounds a single event. Model responses are the largest thing
	// that flows through, and 64 MiB is far above any realistic single chunk
	// while still refusing to allocate unbounded memory from a hostile file.
	MaxPayload = 64 << 20

	// footerSentinel appears in the length field where a frame would start, to
	// mark the end of the frame section. Real lengths are capped at MaxPayload,
	// so the value is unambiguous.
	footerSentinel uint32 = 0xFFFFFFFF
)

// ErrFooter signals that the reader reached the footer rather than a frame. It
// is a control signal, not a failure.
var ErrFooter = errors.New("logfmt: footer reached")

// Frame is one recorded event, decoded.
type Frame struct {
	Kind      Kind
	Seq       uint64
	MonoNanos uint64
	ChainPrev hashchain.Hash
	Payload   []byte

	// Leaf and Chain are the hashes as stored on disk. A reader that wants to
	// trust them must call Validate.
	Leaf  hashchain.Hash
	Chain hashchain.Hash
}

// ComputeLeaf returns the leaf hash this frame's contents imply.
func (f *Frame) ComputeLeaf() hashchain.Hash {
	return hashchain.Leaf(f.Seq, uint8(f.Kind), f.Payload)
}

// Validate checks the frame against its stored leaf hash and against the chain
// value it claims to follow.
//
// The two failures are reported separately on purpose. A payload that disagrees
// with its own leaf hash means those bytes were edited. A leaf that agrees with
// its payload but a chain link that does not means the frame is intact but was
// moved, removed or spliced in. Collapsing both into "invalid" would throw away
// the most useful thing the verifier knows.
//
// Messages carry no sequence number: the caller has f.Seq and adds it once,
// rather than every layer prepending its own copy.
func (f *Frame) Validate(expectedPrev hashchain.Hash) error {
	if got := f.ComputeLeaf(); got != f.Leaf {
		return errors.New("payload does not match its leaf hash")
	}
	if f.ChainPrev != expectedPrev {
		return errors.New("chain predecessor mismatch: the log was spliced or reordered")
	}
	return nil
}

// WriteFrame appends one frame to w and returns the new chain value.
func WriteFrame(w io.Writer, kind Kind, seq, monoNanos uint64, prev hashchain.Hash, payload []byte) (hashchain.Hash, error) {
	if len(payload) > MaxPayload {
		return prev, fmt.Errorf("logfmt: payload of %d bytes exceeds the %d byte limit", len(payload), MaxPayload)
	}

	leaf := hashchain.Leaf(seq, uint8(kind), payload)
	next := hashchain.Chain(prev, leaf)

	buf := make([]byte, 0, frameHeaderSize+len(payload)+frameTrailer)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(payload)))
	buf = append(buf, byte(kind))
	buf = binary.BigEndian.AppendUint64(buf, seq)
	buf = binary.BigEndian.AppendUint64(buf, monoNanos)
	buf = append(buf, prev[:]...)
	buf = append(buf, payload...)
	buf = append(buf, leaf[:]...)

	if _, err := w.Write(buf); err != nil {
		return prev, err
	}
	return next, nil
}

// ReadFrame reads one frame from r.
//
// It returns ErrFooter when the footer sentinel is reached and io.EOF when the
// file simply ends. Those are distinct outcomes: a log that ends without a
// footer is a crashed run, which is expected and still verifiable up to its last
// intact frame, whereas a log that ends at a footer terminated cleanly.
func ReadFrame(r io.Reader) (*Frame, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err // io.EOF or io.ErrUnexpectedEOF, passed through
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == footerSentinel {
		return nil, ErrFooter
	}
	if n > MaxPayload {
		return nil, fmt.Errorf("logfmt: frame claims %d bytes, above the %d byte limit", n, MaxPayload)
	}

	rest := make([]byte, frameHeaderSize-4+int(n)+frameTrailer)
	if _, err := io.ReadFull(r, rest); err != nil {
		// A short read here is a truncated final frame: the run was killed
		// mid-write. Report it distinctly so the caller can keep the verified
		// prefix instead of discarding the whole bundle.
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}

	f := &Frame{
		Kind:      Kind(rest[0]),
		Seq:       binary.BigEndian.Uint64(rest[1:9]),
		MonoNanos: binary.BigEndian.Uint64(rest[9:17]),
	}
	copy(f.ChainPrev[:], rest[17:17+hashchain.Size])

	payloadStart := 17 + hashchain.Size
	f.Payload = rest[payloadStart : payloadStart+int(n)]
	copy(f.Leaf[:], rest[payloadStart+int(n):])
	f.Chain = hashchain.Chain(f.ChainPrev, f.Leaf)

	return f, nil
}

// WriteFooterSentinel emits the marker that separates frames from the footer.
func WriteFooterSentinel(w io.Writer) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], footerSentinel)
	_, err := w.Write(b[:])
	return err
}
