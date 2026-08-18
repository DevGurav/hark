// Package report renders a bundle as one self-contained HTML file.
//
// No server, no framework, no external request. A single file can be attached
// to an issue, mailed to a reviewer, or opened on a machine with no network,
// which is more than can be said for a viewer that has to be running. It is
// also why there is no JavaScript here: the expandable sections are <details>
// elements, so the page works with scripting disabled and cannot be broken by a
// CDN that has moved on.
//
// This is a view of a bundle, never a substitute for verifying one. The header
// says what `hark verify` found; it does not re-derive it in the browser.
package report

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/logfmt"
)

// Options controls the rendering.
type Options struct {
	// MaxBody bounds how much of any one body is rendered. A recorded response
	// can be megabytes, and a browser handed all of them at once stops being a
	// way to read a run.
	MaxBody int

	// Anchor is what the transparency log had to say, already checked by the
	// caller. The report does not make network calls of its own.
	Anchor string

	// Summarise renders one event as a line. Supplied by the caller so the
	// report and `hark inspect` cannot drift into describing the same event two
	// different ways.
	Summarise func(*logfmt.Frame) string

	// Verified is what the verifier already found, when the caller has it.
	// Verification is a full pass over the bundle -- a quarter of a second at
	// 100k events -- and the CLI has to run it anyway to decide what to ask the
	// transparency log. Nil means verify here.
	Verified *bundle.Result
}

const defaultMaxBody = 4 << 10

// Render writes the report for the bundle at path.
func Render(w io.Writer, path string, opt Options) error {
	if opt.MaxBody <= 0 {
		opt.MaxBody = defaultMaxBody
	}
	if opt.Summarise == nil {
		return errors.New("report: no summariser supplied")
	}

	res := opt.Verified
	if res == nil {
		var err error
		if res, err = bundle.Verify(path); err != nil {
			return err
		}
	}

	r, err := bundle.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()

	h := r.Header()
	p := &page{
		Path:      path,
		RunID:     h.RunID,
		Recorder:  h.Recorder,
		Created:   time.Unix(0, h.CreatedAt).UTC().Format(time.RFC3339),
		Status:    string(res.Status),
		Events:    res.LeafCount,
		Root:      fmt.Sprintf("%x", res.Root),
		Chain:     fmt.Sprintf("%x", res.FinalChain),
		Anchor:    opt.Anchor,
		Problem:   res.Problem,
		Generated: time.Now().UTC().Format(time.RFC3339),
	}
	switch {
	case !res.Signed:
		p.Signature = "absent"
	case res.SignatureOK:
		p.Signature = fmt.Sprintf("ok, key %x", res.PublicKey)
	default:
		p.Signature = "FAILED"
	}
	if len(h.ParentRoot) > 0 {
		p.Parent = &parent{
			Root:  fmt.Sprintf("%x", h.ParentRoot),
			Point: h.ForkPoint,
			Patch: fmt.Sprintf("%x", h.PatchHash),
		}
	}

	for {
		f, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			p.Killed = true
			break
		}
		if err != nil {
			return err
		}
		p.Rows = append(p.Rows, buildRow(f, opt))
	}

	for k, n := range res.KindCounts {
		p.Counts = append(p.Counts, count{Kind: k.String(), N: n})
	}
	sort.Slice(p.Counts, func(i, j int) bool { return p.Counts[i].Kind < p.Counts[j].Kind })

	return tmpl.Execute(w, p)
}

type page struct {
	Path      string
	RunID     string
	Recorder  string
	Created   string
	Generated string

	Status    string
	Events    uint64
	Root      string
	Chain     string
	Signature string
	Anchor    string
	Problem   string
	Killed    bool

	Parent *parent
	Rows   []row
	Counts []count
}

type parent struct {
	Root  string
	Point uint64
	Patch string
}

type count struct {
	Kind string
	N    uint64
}

type row struct {
	Seq     uint64
	At      string
	Kind    string
	Class   string
	Summary string
	Fields  []field
	Body    string
	BodyOf  string
	More    int
}

type field struct {
	Name  string
	Value string
}

// buildRow turns one frame into a table row with its expandable detail.
func buildRow(f *logfmt.Frame, opt Options) row {
	r := row{
		Seq:     f.Seq,
		At:      time.Duration(f.MonoNanos).Round(time.Millisecond).String(),
		Kind:    f.Kind.String(),
		Summary: opt.Summarise(f),
		Class:   class(f),
	}

	switch f.Kind {
	case logfmt.KindRunStart:
		var v logfmt.RunStart
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"command", strings.Join(v.Argv, " ")},
				{"working directory", v.WorkingDir},
				{"hosts the mediator would broker", strings.Join(v.ProviderSet, ", ")},
			}
			if len(v.Upstreams) > 0 {
				// Prominent on purpose: a run with a redirected upstream did not
				// reach the host its events name, and a reader has to see that
				// before believing the rest of the page.
				r.Fields = append(r.Fields, field{"upstream redirected", strings.Join(v.Upstreams, ", ")})
			}
		}

	case logfmt.KindPolicyLoaded:
		var v logfmt.PolicyLoaded
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"source", v.Source},
				{"allowed hosts", strings.Join(v.AllowHosts, ", ")},
				{"readable", strings.Join(v.ReadPaths, ", ")},
				{"writable", strings.Join(v.WritePaths, ", ")},
			}
			r.Body, r.More = clip(v.Raw, opt.MaxBody)
			r.BodyOf = "policy as loaded"
		}

	case logfmt.KindEnvSnapshot:
		var v logfmt.EnvSnapshot
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			names := make([]string, 0, len(v.Vars))
			for k := range v.Vars {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				r.Fields = append(r.Fields, field{k, v.Vars[k]})
			}
		}

	case logfmt.KindLLMRequest:
		var v logfmt.LLMRequest
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"host", v.Host},
				{"method", v.Method},
				{"path", v.Path},
				{"occurrence", fmt.Sprint(v.Occurrence)},
				{"exchange", fmt.Sprint(v.Exchange)},
				{"request key", fmt.Sprintf("%x", v.RequestKey)},
			}
			r.Fields = append(r.Fields, headerFields(v.Headers)...)
			r.Body, r.More = clip(v.Body, opt.MaxBody)
			r.BodyOf = "request body as the agent sent it"
		}

	case logfmt.KindLLMResponseChunk:
		var v logfmt.LLMResponseChunk
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"chunk", fmt.Sprint(v.Seq)},
				{"exchange", fmt.Sprint(v.Exchange)},
				{"since the previous chunk", time.Duration(v.SincePrev).Round(time.Millisecond).String()},
			}
			r.Body, r.More = clip(v.Data, opt.MaxBody)
			r.BodyOf = "chunk as it arrived on the wire"
		}

	case logfmt.KindLLMResponseEnd:
		var v logfmt.LLMResponseEnd
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"status", fmt.Sprint(v.Status)},
				{"chunks", fmt.Sprint(v.ChunkCount)},
				{"exchange", fmt.Sprint(v.Exchange)},
			}
			if v.Error != "" {
				r.Fields = append(r.Fields, field{"error", v.Error})
			}
			r.Fields = append(r.Fields, headerFields(v.Headers)...)
		}

	case logfmt.KindEgressAttempt:
		var v logfmt.EgressAttempt
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"host", v.Host}, {"port", fmt.Sprint(v.Port)},
				{"protocol", v.Protocol}, {"server name", v.SNI},
			}
		}

	case logfmt.KindEgressDecision:
		var v logfmt.EgressDecision
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"host", v.Host}, {"allowed", fmt.Sprint(v.Allowed)},
				{"rule", v.Rule}, {"reason", v.Reason},
			}
		}

	case logfmt.KindDNSQuery:
		var v logfmt.DNSQuery
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{{"name", v.Name}, {"type", v.Type}}
		}

	case logfmt.KindDNSDecision:
		var v logfmt.DNSDecision
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"name", v.Name}, {"allowed", fmt.Sprint(v.Allowed)},
				{"rule", v.Rule}, {"answer", v.Answer}, {"reason", v.Reason},
			}
		}

	case logfmt.KindSecretInjected:
		var v logfmt.SecretInjected
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"reference", v.Ref},
				{"what the agent held", v.Placeholder},
				{"host", v.Host},
				{"value hash", fmt.Sprintf("%x", v.ValueHash)},
			}
		}

	case logfmt.KindClockRead:
		var v logfmt.ClockRead
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{{"source", v.Source}, {"nanoseconds", fmt.Sprint(v.Value)}}
		}

	case logfmt.KindRandomRead:
		var v logfmt.RandomRead
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{{"source", v.Source}}
			r.Body, r.More = clip(v.Data, opt.MaxBody)
			r.BodyOf = "value as recorded"
		}

	case logfmt.KindToolCallRequest:
		var v logfmt.ToolCallRequest
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"server", v.Server}, {"tool", v.Tool},
				{"occurrence", fmt.Sprint(v.Occurrence)}, {"exchange", fmt.Sprint(v.Exchange)},
			}
			r.Body, r.More = clip(v.Arguments, opt.MaxBody)
			r.BodyOf = "arguments"
		}

	case logfmt.KindToolCallResult:
		var v logfmt.ToolCallResult
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{
				{"server", v.Server}, {"tool", v.Tool},
				{"error", fmt.Sprint(v.IsError)}, {"exchange", fmt.Sprint(v.Exchange)},
			}
			r.Body, r.More = clip(v.Result, opt.MaxBody)
			r.BodyOf = "result"
		}

	case logfmt.KindRunEnd:
		var v logfmt.RunEnd
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			r.Fields = []field{{"exit code", fmt.Sprint(v.ExitCode)}, {"reason", v.Reason}}
		}
	}
	return r
}

// class marks the rows worth finding at a glance.
func class(f *logfmt.Frame) string {
	switch f.Kind {
	case logfmt.KindEgressDecision:
		var v logfmt.EgressDecision
		if logfmt.Unmarshal(f.Payload, &v) == nil && !v.Allowed {
			return "denial"
		}
	case logfmt.KindDNSDecision:
		var v logfmt.DNSDecision
		if logfmt.Unmarshal(f.Payload, &v) == nil && !v.Allowed {
			return "denial"
		}
	case logfmt.KindSecretInjected:
		return "secret"
	case logfmt.KindRunStart, logfmt.KindRunEnd:
		return "framing"
	}
	return ""
}

func headerFields(h map[string]string) []field {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)

	out := make([]field, 0, len(names))
	for _, k := range names {
		out = append(out, field{k, h[k]})
	}
	return out
}

// clip renders a body for display, bounded, and says how much was left out.
//
// Anything that is not valid UTF-8 is hex-dumped rather than mangled into
// replacement characters: a reader looking at a recorded body needs to see what
// was there, and a lossy rendering of binary is worse than an honest one.
func clip(b []byte, max int) (string, int) {
	if len(b) == 0 {
		return "", 0
	}
	more := 0
	if len(b) > max {
		more = len(b) - max
		b = b[:max]
	}
	if !utf8.Valid(b) {
		return hex.Dump(b), more
	}
	return string(b), more
}
