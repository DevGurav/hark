// Package bundle reads and writes .hark files.
//
// # File layout
//
//	"HARK" 0x01              magic and format version
//	u32 + CBOR               header
//	frames...                see logfmt
//	u32 0xFFFFFFFF           footer sentinel
//	u32 + CBOR               footer
//
// A bundle whose footer is missing is not corrupt -- it is a run that was killed
// before it could seal. Everything up to the last intact frame still verifies
// against the hash chain, which is exactly why the chain exists alongside the
// Merkle root.
//
// The MMR is not persisted. It is recomputed from the frames whenever a proof is
// needed, which costs one linear pass over a file that is being read anyway.
// Storing roughly 2N interior nodes to save that pass would double bundle size
// for an operation that runs far less often than verification does.
package bundle

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/mmr"
	"github.com/DevGurav/hark/internal/signer"
)

var magic = [5]byte{'H', 'A', 'R', 'K', 0x01}

// FormatVersion is bumped only for changes that older readers cannot tolerate.
const FormatVersion = 1

// Header is written before any frame and holds what a reader needs in order to
// interpret the frames that follow.
type Header struct {
	RunID      string `cbor:"1,keyasint"`
	CreatedAt  int64  `cbor:"2,keyasint"` // Unix nanoseconds
	Recorder   string `cbor:"3,keyasint"` // hark version string
	ArgvHash   []byte `cbor:"4,keyasint"`
	PolicyHash []byte `cbor:"5,keyasint"`
	EnvHash    []byte `cbor:"6,keyasint"`
	ParentRoot []byte `cbor:"7,keyasint"` // set on forked runs
	ForkPoint  uint64 `cbor:"8,keyasint"`
	PatchHash  []byte `cbor:"9,keyasint"`
}

// Footer seals a completed run.
type Footer struct {
	LeafCount  uint64      `cbor:"1,keyasint"`
	Root       []byte      `cbor:"2,keyasint"` // MMR root
	FinalChain []byte      `cbor:"3,keyasint"` // last chain value
	STH        *signer.STH `cbor:"4,keyasint"`
	RekorEntry string      `cbor:"5,keyasint"` // transparency log reference, empty if unanchored
	RekorIndex int64       `cbor:"6,keyasint"`
}

// ---------- writing ----------

// Writer appends events to a bundle, maintaining the hash chain and the MMR as
// it goes.
type Writer struct {
	f      *os.File
	w      *bufio.Writer
	header Header

	seq   uint64
	chain hashchain.Hash
	tree  *mmr.MMR

	sealed bool
}

// Create starts a new bundle at path.
func Create(path string, h Header) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	bw := bufio.NewWriterSize(f, 1<<16)
	if _, err := bw.Write(magic[:]); err != nil {
		f.Close()
		return nil, err
	}
	if err := writeBlock(bw, h); err != nil {
		f.Close()
		return nil, err
	}
	// Get the magic and header out immediately, so the file is a readable bundle
	// from the moment it exists rather than from the first flush.
	if err := bw.Flush(); err != nil {
		f.Close()
		return nil, err
	}

	return &Writer{f: f, w: bw, header: h, tree: mmr.New()}, nil
}

// Append writes one event and returns its sequence number.
func (w *Writer) Append(kind logfmt.Kind, monoNanos uint64, payload any) (uint64, error) {
	if w.sealed {
		return 0, errors.New("bundle: append after seal")
	}

	body, err := logfmt.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("bundle: encoding %s: %w", kind, err)
	}

	seq := w.seq
	next, err := logfmt.WriteFrame(w.w, kind, seq, monoNanos, w.chain, body)
	if err != nil {
		return 0, err
	}

	// Hand every frame to the operating system as it is written.
	//
	// This is what makes "a killed run leaves a verifiable prefix" true rather
	// than merely intended. Buffered in userspace, a SIGKILL loses everything
	// still in the buffer -- which for a short run is the entire bundle, leaving
	// a zero-length file that cannot even be opened. Flushing per frame means the
	// prefix survives anything short of the machine going down.
	//
	// It costs one write syscall per event, against a log whose events are
	// produced by network round trips. Sync, which is the expensive one, stays
	// reserved for denials.
	if err := w.w.Flush(); err != nil {
		return 0, err
	}

	w.chain = next
	w.tree.Add(hashchain.Leaf(seq, uint8(kind), body))
	w.seq++
	return seq, nil
}

// Root returns the current MMR root. Callable mid-run, which is what makes
// periodic tree heads possible.
func (w *Writer) Root() hashchain.Hash { return w.tree.Root() }

// LeafCount returns how many events have been appended.
func (w *Writer) LeafCount() uint64 { return w.seq }

// Sync flushes buffered frames to the operating system and then to stable
// storage.
//
// Called at the point where losing events would matter -- notably after an
// egress denial, because the denial is the evidence the whole bundle exists to
// carry, and a crash immediately afterwards must not be able to erase it.
func (w *Writer) Sync() error {
	if err := w.w.Flush(); err != nil {
		return err
	}
	return w.f.Sync()
}

// Seal writes the footer and closes the file.
func (w *Writer) Seal(key *signer.Key, signedAt int64, rekorEntry string, rekorIndex int64) (*Footer, error) {
	if w.sealed {
		return nil, errors.New("bundle: already sealed")
	}
	w.sealed = true

	root := w.tree.Root()
	foot := Footer{
		LeafCount:  w.seq,
		Root:       root[:],
		FinalChain: w.chain[:],
		RekorEntry: rekorEntry,
		RekorIndex: rekorIndex,
	}
	if key != nil {
		foot.STH = key.Sign(w.header.RunID, w.seq, root, signedAt)
	}

	if err := logfmt.WriteFooterSentinel(w.w); err != nil {
		return nil, err
	}
	if err := writeBlock(w.w, foot); err != nil {
		return nil, err
	}
	if err := w.w.Flush(); err != nil {
		return nil, err
	}
	if err := w.f.Sync(); err != nil {
		return nil, err
	}
	return &foot, w.f.Close()
}

// Abort closes the file without a footer, leaving a verifiable prefix behind.
func (w *Writer) Abort() error {
	w.sealed = true
	if err := w.w.Flush(); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}

func writeBlock(w io.Writer, v any) error {
	body, err := logfmt.Marshal(v)
	if err != nil {
		return err
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// ---------- reading ----------

// Reader streams a bundle from disk.
type Reader struct {
	f      *os.File
	r      *bufio.Reader
	header Header
	footer *Footer
}

// Open reads the magic and header, leaving the reader positioned at the first
// frame.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(f, 1<<16)

	var m [5]byte
	if _, err := io.ReadFull(br, m[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("bundle: reading magic: %w", err)
	}
	if m != magic {
		f.Close()
		if string(m[:4]) == "HARK" {
			return nil, fmt.Errorf("bundle: format version %d, this build understands %d", m[4], FormatVersion)
		}
		return nil, errors.New("bundle: not a hark bundle")
	}

	rd := &Reader{f: f, r: br}
	if err := readBlock(br, &rd.header); err != nil {
		f.Close()
		return nil, fmt.Errorf("bundle: reading header: %w", err)
	}
	return rd, nil
}

// Header returns the parsed header.
func (r *Reader) Header() Header { return r.header }

// Footer returns the footer, available only after frames have been read to the
// end. It is nil for an unsealed bundle.
func (r *Reader) Footer() *Footer { return r.footer }

// Next returns the next frame, io.EOF at a clean end, or io.ErrUnexpectedEOF if
// the final frame was truncated.
func (r *Reader) Next() (*logfmt.Frame, error) {
	f, err := logfmt.ReadFrame(r.r)
	if errors.Is(err, logfmt.ErrFooter) {
		var foot Footer
		if err := readBlock(r.r, &foot); err != nil {
			return nil, fmt.Errorf("bundle: reading footer: %w", err)
		}
		r.footer = &foot
		return nil, io.EOF
	}
	return f, err
}

// Close releases the underlying file.
func (r *Reader) Close() error { return r.f.Close() }

func readBlock(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > logfmt.MaxPayload {
		return fmt.Errorf("bundle: block claims %d bytes, above the limit", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return logfmt.Unmarshal(body, v)
}
