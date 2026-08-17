// Package shim is the supervisor's side of the in-process capture channel.
//
// The mediator sees everything crossing the network boundary. A clock read and a
// random draw never cross it, but both change what an agent does, so replay
// needs them too. The Python shim patches those functions and reports each call
// here over a unix socket.
//
// Enforced versus advisory is worth keeping straight. The kernel enforces the
// network boundary; nothing enforces this one. An agent can remove the shim from
// its PYTHONPATH or call the syscalls directly, so clock and RNG fidelity are
// best-effort. That is stated in docs/security.md rather than left implicit.
package shim

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/DevGurav/hark/internal/logfmt"
)

// Recorder is the shim's view of the event log.
type Recorder interface {
	Append(kind logfmt.Kind, payload any) (uint64, error)
}

// Mode selects recording or playback.
type Mode string

const (
	ModeRecord Mode = "record"
	ModeReplay Mode = "replay"

	// ModeFork is replay that turns into recording part-way through: recorded
	// values up to the fork point, real ones after it.
	//
	// The switch has to be visible to the agent's process rather than handled
	// entirely here, because only the agent can produce a value of the right
	// shape. The supervisor knows a uuid was drawn; it does not know how to make
	// one that the agent's uuid module will accept, and guessing at that is how
	// a fork would end up feeding an agent something it could never have
	// produced.
	ModeFork Mode = "fork"
)

// Server accepts shim connections on a unix socket.
type Server struct {
	path     string
	mode     Mode
	recorder Recorder

	// Live reports whether a forked run has passed its fork point. Set before
	// Serve when the mode is ModeFork; ignored otherwise. Nil means the fork
	// point is never reached, which serves the whole recording.
	Live func() bool

	mu sync.Mutex
	// queues holds, per source, the values recorded in order. Replay consumes
	// from the front.
	queues map[string][]json.RawMessage

	ln        net.Listener
	closeOnce sync.Once
}

// Values is the recorded clock and RNG history, grouped by source.
type Values map[string][]json.RawMessage

// New creates a server. dir is where the socket is placed; it must be a
// directory the agent can reach.
//
// The socket lives in the run directory rather than the agent's workspace on
// purpose: the workspace is writable by the agent, and a control channel it can
// unlink or replace is not a control channel.
func New(dir string, mode Mode, rec Recorder, recorded Values) (*Server, error) {
	switch mode {
	case ModeRecord, ModeReplay, ModeFork:
	default:
		return nil, fmt.Errorf("shim: unknown mode %q", mode)
	}
	if mode != ModeReplay && rec == nil {
		return nil, errors.New("shim: recording needs a recorder")
	}

	s := &Server{
		path:     filepath.Join(dir, "shim.sock"),
		mode:     mode,
		recorder: rec,
		queues:   make(map[string][]json.RawMessage, len(recorded)),
	}
	for src, vals := range recorded {
		s.queues[src] = append([]json.RawMessage(nil), vals...)
	}
	return s, nil
}

// Path is the socket the agent should connect to.
func (s *Server) Path() string { return s.path }

// Env returns the variables the agent needs to find and use the shim.
func (s *Server) Env(shimDir string) []string {
	return []string{
		"HARK_SHIM_SOCKET=" + s.path,
		"HARK_SHIM_MODE=" + string(s.mode),
		"PYTHONPATH=" + shimDir,
		// Without a fixed hash seed, the iteration order of a set or a dict keyed
		// by strings varies per process. Anything an agent derives from that
		// order -- and dict ordering leaks into prompt construction more often
		// than people expect -- would differ on replay.
		"PYTHONHASHSEED=0",
	}
}

// Serve accepts connections until Close.
func (s *Server) Serve() error {
	_ = os.Remove(s.path) // a stale socket from a killed run would block the bind

	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("shim: listening on %s: %w", s.path, err)
	}
	s.ln = ln

	// The agent runs as a different, unprivileged identity in a real run, so the
	// socket has to be reachable by it.
	if err := os.Chmod(s.path, 0o666); err != nil {
		return fmt.Errorf("shim: opening the socket to the agent: %w", err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil // closed
		}
		go s.handle(conn)
	}
}

// Close stops the server and removes the socket.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		if s.ln != nil {
			s.ln.Close()
		}
		_ = os.Remove(s.path)
	})
	return nil
}

type request struct {
	Op  string          `json:"op"`
	Src string          `json:"src"`
	Val json.RawMessage `json:"val,omitempty"`
}

type reply struct {
	OK  bool            `json:"ok"`
	Val json.RawMessage `json:"val,omitempty"`
	Err string          `json:"err,omitempty"`

	// Live tells a forked run to produce a real value and report it back with
	// "rec". Only ever set in ModeFork.
	Live bool `json:"live,omitempty"`
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}

		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.write(w, reply{Err: "malformed request"})
			return
		}

		switch req.Op {
		case "rec":
			s.write(w, s.record(req))
		case "get":
			s.write(w, s.serve(req))
		default:
			s.write(w, reply{Err: "unknown op " + req.Op})
			return
		}
	}
}

func (s *Server) write(w *bufio.Writer, rep reply) {
	body, err := json.Marshal(rep)
	if err != nil {
		return
	}
	_, _ = w.Write(append(body, '\n'))
	_ = w.Flush()
}

// record appends a captured value to the log.
func (s *Server) record(req request) reply {
	if s.mode == ModeReplay {
		return reply{Err: "not recording"}
	}

	// The queue is what a later replay would be served from, so a recording run
	// keeps its values there. A fork must not: its queue holds what the parent
	// recorded and has not yet handed over, and appending the child's own draws
	// to it would conflate two different runs in one list.
	if s.mode == ModeRecord {
		s.mu.Lock()
		s.queues[req.Src] = append(s.queues[req.Src], append(json.RawMessage(nil), req.Val...))
		s.mu.Unlock()
	}

	s.appendEvent(req.Src, req.Val)
	return reply{OK: true}
}

// serve returns the next recorded value for a source.
//
// Running out is a divergence, not a condition to paper over: the replayed run
// asked for more randomness than the recording contains, which means it took a
// different path. Inventing a value here would let replay report success over a
// run that did something else.
func (s *Server) serve(req request) reply {
	switch s.mode {
	case ModeReplay:
	case ModeFork:
		// Past the fork point the recording is no longer the authority on what
		// this run does, so the agent draws for real and reports the value back.
		// The remaining recorded values are left in the queue: they belong to the
		// run that was, not to the one being explored.
		if s.Live != nil && s.Live() {
			return reply{OK: true, Live: true}
		}
	default:
		return reply{Err: "not replaying"}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	queue := s.queues[req.Src]
	if len(queue) == 0 {
		return reply{Err: fmt.Sprintf(
			"the recording has no more %s values; the replayed run diverged", req.Src)}
	}
	val := queue[0]
	s.queues[req.Src] = queue[1:]

	// Record on the way out as well as on the way in.
	//
	// A replayed run has to produce the same events as the recording, or the
	// action sequences differ by exactly the reads the shim served and every
	// replay reports a divergence it caused itself. It also means the replayed
	// bundle is a complete recording in its own right, and can be replayed again.
	if s.recorder != nil {
		s.appendEvent(req.Src, val)
	}
	return reply{OK: true, Val: val}
}

// appendEvent writes one captured value to the log.
func (s *Server) appendEvent(src string, val json.RawMessage) {
	if isClock(src) {
		_, _ = s.recorder.Append(logfmt.KindClockRead,
			logfmt.ClockRead{Source: src, Value: clockNanos(src, val)})
		return
	}
	_, _ = s.recorder.Append(logfmt.KindRandomRead,
		logfmt.RandomRead{Source: src, Data: val})
}

// Remaining reports how many recorded values were never consumed, per source.
//
// A replay that leaves values behind took a shorter path than the recording.
// Not an error by itself, but worth surfacing in the replay summary.
func (s *Server) Remaining() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[string]int, len(s.queues))
	for src, q := range s.queues {
		if len(q) > 0 {
			out[src] = len(q)
		}
	}
	return out
}

func isClock(src string) bool {
	switch src {
	case "time.time", "time.monotonic", "time.time_ns", "time.monotonic_ns":
		return true
	}
	return false
}

// clockNanos renders a clock reading in nanoseconds for the event log.
//
// The float variants report seconds and the _ns ones report integers, so the
// log would otherwise mix units under one field. The replay channel still serves
// back the original JSON, so the agent sees exactly the value it saw before --
// this conversion is for the human reading `hark inspect`.
func clockNanos(src string, raw json.RawMessage) int64 {
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0
	}
	if src == "time.time_ns" || src == "time.monotonic_ns" {
		return int64(f)
	}
	return int64(f * 1e9)
}

// snapshot returns the values captured so far, for handing to a replaying
// server. Used by tests and by `hark replay` when it builds playback state from
// a recording it just made.
func (s *Server) snapshot() Values {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(Values, len(s.queues))
	for src, q := range s.queues {
		out[src] = append([]json.RawMessage(nil), q...)
	}
	return out
}

// Snapshot is the exported form of snapshot.
func (s *Server) Snapshot() Values { return s.snapshot() }
