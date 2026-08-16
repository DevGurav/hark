// Package replay reads a recorded bundle and serves its responses back.
//
// Replay does not re-derive what the model said; it returns what the model
// actually said, recorded at the boundary. That distinction is the project's
// central caveat and it lives here: hosted inference is not reproducible even at
// temperature zero, so the only sound thing to do is play back the recording.
//
// What replay *does* establish is that the harness behaves identically given
// identical external inputs -- the same sequence of externally-visible actions,
// and the same log root.
package replay

import (
	"errors"
	"fmt"
	"io"

	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/reqkey"
)

// Response is one recorded upstream reply.
type Response struct {
	Status     int
	Headers    map[string]string
	Chunks     [][]byte
	Error      string
	Exchange   uint64
	Occurrence uint32
}

// Source indexes a recorded run for playback.
type Source struct {
	RunID     string
	Root      hashchain.Hash
	LeafCount uint64

	// byKey maps a request's canonical hash to its responses, in the order they
	// occurred. The slice index is the occurrence ordinal, so a retry finds its
	// own answer rather than the one before it.
	byKey map[hashchain.Hash][]*Response

	// Consumed counts lookups that matched, for the replay summary.
	consumed map[hashchain.Hash]uint32
}

// ErrNoMatch means the replayed run asked for something the recording does not
// contain.
//
// This is deliberately fatal to a replay rather than a fallback. A replayer that
// guesses -- serving the nearest response, or the next one in sequence -- can
// report success while feeding the agent an answer it never received, which is
// the failure mode that would make every replay result untrustworthy.
var ErrNoMatch = errors.New("replay: no recorded response for this request")

// Load reads a bundle and indexes its exchanges.
func Load(path string) (*Source, error) {
	r, err := bundle.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	s := &Source{
		RunID:    r.Header().RunID,
		byKey:    make(map[hashchain.Hash][]*Response),
		consumed: make(map[hashchain.Hash]uint32),
	}

	// Exchanges are assembled by correlation id rather than by position, because
	// concurrent connections interleave their events in the log.
	type pending struct {
		key hashchain.Hash
		occ uint32
		res *Response
	}
	open := make(map[uint64]*pending)

	for {
		f, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// A truncated recording is still usable up to its last intact frame.
			// Whatever exchanges completed can be replayed; the rest simply are
			// not there, and a replay that reaches them fails with ErrNoMatch.
			break
		}
		if err != nil {
			return nil, err
		}

		switch f.Kind {
		case logfmt.KindLLMRequest:
			var v logfmt.LLMRequest
			if err := logfmt.Unmarshal(f.Payload, &v); err != nil {
				return nil, fmt.Errorf("replay: decoding request at seq %d: %w", f.Seq, err)
			}
			var key hashchain.Hash
			if len(v.RequestKey) != hashchain.Size {
				return nil, fmt.Errorf("replay: request at seq %d has a %d-byte key", f.Seq, len(v.RequestKey))
			}
			copy(key[:], v.RequestKey)
			open[v.Exchange] = &pending{
				key: key,
				occ: v.Occurrence,
				res: &Response{Exchange: v.Exchange, Occurrence: v.Occurrence},
			}

		case logfmt.KindLLMResponseChunk:
			var v logfmt.LLMResponseChunk
			if err := logfmt.Unmarshal(f.Payload, &v); err != nil {
				return nil, fmt.Errorf("replay: decoding chunk at seq %d: %w", f.Seq, err)
			}
			if p, ok := open[v.Exchange]; ok {
				p.res.Chunks = append(p.res.Chunks, v.Data)
			}

		case logfmt.KindLLMResponseEnd:
			var v logfmt.LLMResponseEnd
			if err := logfmt.Unmarshal(f.Payload, &v); err != nil {
				return nil, fmt.Errorf("replay: decoding response end at seq %d: %w", f.Seq, err)
			}
			p, ok := open[v.Exchange]
			if !ok {
				// An end with no request: a handshake or dial failure, recorded
				// with no exchange of its own. Nothing to index.
				continue
			}
			p.res.Status = v.Status
			p.res.Headers = v.Headers
			p.res.Error = v.Error
			s.insert(p.key, p.occ, p.res)
			delete(open, v.Exchange)
		}
	}

	// An exchange with no end marker is one the run was killed part-way through.
	// It is left unindexed rather than served as a truncated response, so replay
	// reaching it fails loudly instead of handing the agent half an answer.

	if foot := r.Footer(); foot != nil {
		s.LeafCount = foot.LeafCount
		copy(s.Root[:], foot.Root)
	}
	return s, nil
}

// insert places a response at its occurrence index, growing the slice as needed.
//
// Ordinals are used as positions rather than assumed sequential, because a
// truncated recording can be missing one in the middle.
func (s *Source) insert(key hashchain.Hash, occ uint32, res *Response) {
	list := s.byKey[key]
	for uint32(len(list)) <= occ {
		list = append(list, nil)
	}
	list[occ] = res
	s.byKey[key] = list
}

// Lookup returns the recorded response for a request, advancing that request's
// occurrence counter.
func (s *Source) Lookup(canonical []byte) (*Response, error) {
	k := reqkey.Peek(canonical, s.consumed)

	list := s.byKey[k.Hash]
	if uint32(len(list)) <= k.Occurrence || list[k.Occurrence] == nil {
		if len(list) == 0 {
			return nil, fmt.Errorf("%w: request %s was never recorded", ErrNoMatch, k)
		}
		return nil, fmt.Errorf("%w: request %s recorded %d time(s), this is occurrence %d",
			ErrNoMatch, k, len(list), k.Occurrence)
	}

	s.consumed[k.Hash] = k.Occurrence + 1
	return list[k.Occurrence], nil
}

// Exchanges reports how many request/response pairs were indexed.
func (s *Source) Exchanges() int {
	var n int
	for _, list := range s.byKey {
		for _, r := range list {
			if r != nil {
				n++
			}
		}
	}
	return n
}

// Unconsumed reports how many recorded responses were never asked for.
//
// Not an error on its own -- an agent may legitimately take a shorter path the
// second time. It is worth surfacing though, because a replay that consumed far
// fewer responses than were recorded usually means the run diverged early.
func (s *Source) Unconsumed() int {
	var n int
	for key, list := range s.byKey {
		used := int(s.consumed[key])
		for i, r := range list {
			if r != nil && i >= used {
				n++
			}
		}
	}
	return n
}
