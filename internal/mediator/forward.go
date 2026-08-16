package mediator

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/reqkey"
)

// Forwarding an allowed connection.
//
// The mediator terminates the agent's TLS with a certificate from the run's own
// CA, opens a real TLS connection to the upstream host, and passes requests
// between them -- recording both sides and substituting real credentials on the
// way out.
//
// The agent's copy of a request holds a placeholder; only the copy sent upstream
// holds the credential. That is enforced by the broker returning copies rather
// than mutating, so the recorded request cannot accidentally be the injected
// one.

// forwardTimeout bounds a single upstream exchange. Model calls are slow, so
// this is generous; it exists to stop a hung upstream pinning a goroutine and a
// namespace open indefinitely.
const forwardTimeout = 10 * time.Minute

func (m *Mediator) forward(conn net.Conn, host string) {
	// http/1.1 only. Without pinning ALPN the client may negotiate h2, and
	// framed multiplexing would have to be unpacked before anything could be
	// recorded per request. HTTP/1.1 costs a little throughput the agent will
	// never notice next to model latency.
	cfg := m.ca.TLSConfig()
	cfg.NextProtos = []string{"http/1.1"}

	agent := tls.Server(conn, cfg)
	if err := agent.Handshake(); err != nil {
		// Most often a client that pins certificates, which is a documented
		// limitation rather than an attack. Recorded either way.
		m.record(logfmt.KindLLMResponseEnd, logfmt.LLMResponseEnd{
			Error: "TLS handshake with the agent failed: " + err.Error(),
		})
		return
	}
	defer agent.Close()

	agentReader := bufio.NewReader(agent)

	// In playback there is no upstream at all. That is the property worth
	// stating: a replayed run opens no outbound connection, so it cannot have
	// side effects, cannot cost money, and cannot be affected by whether the
	// endpoint happens to be up.
	if m.cfg.Playback != nil {
		for {
			_ = agent.SetReadDeadline(time.Now().Add(forwardTimeout))
			req, err := http.ReadRequest(agentReader)
			if err != nil {
				return
			}
			if err := m.exchange(req, host, nil, nil, agent); err != nil {
				return
			}
		}
	}

	dial := m.cfg.DialUpstream
	if dial == nil {
		dial = func(h string) (net.Conn, error) {
			return tls.Dial("tcp", net.JoinHostPort(h, "443"), &tls.Config{
				ServerName: h,
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"http/1.1"},
			})
		}
	}

	upstream, err := dial(host)
	if err != nil {
		m.record(logfmt.KindLLMResponseEnd, logfmt.LLMResponseEnd{
			Error: "connecting to " + host + ": " + err.Error(),
		})
		return
	}
	defer upstream.Close()

	upstreamReader := bufio.NewReader(upstream)

	for {
		_ = agent.SetReadDeadline(time.Now().Add(forwardTimeout))
		req, err := http.ReadRequest(agentReader)
		if err != nil {
			return // agent closed the connection, or sent something unparseable
		}

		if err := m.exchange(req, host, upstream, upstreamReader, agent); err != nil {
			return
		}
	}
}

// exchange records and forwards one request/response pair.
func (m *Mediator) exchange(req *http.Request, host string, upstream net.Conn, upstreamReader *bufio.Reader, agent net.Conn) error {
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return err
	}

	// Record what the agent sent, placeholders and all, before injection. The
	// broker works on copies, so this is the untouched original by construction.
	//
	// The key is derived with the same canonicalisation replay will use. Two
	// implementations of "what makes this request the same request" would drift,
	// and the way that failure shows up is replay serving the wrong response and
	// reporting success.
	canonical := reqkey.Canonicalise(req.Method, host, req.URL.RequestURI(), req.Header, body)
	key := m.keyFor(canonical)
	exchange := m.exchangeSeq.Add(1)

	recorded := logfmt.LLMRequest{
		Host:       host,
		Method:     req.Method,
		Path:       req.URL.RequestURI(),
		Headers:    flatten(req.Header),
		Body:       body,
		RequestKey: key.Hash[:],
		Occurrence: key.Occurrence,
		Exchange:   exchange,
	}
	m.record(logfmt.KindLLMRequest, recorded)

	// Playback answers from the recording and never dials out.
	if m.cfg.Playback != nil {
		res, err := m.cfg.Playback.Lookup(canonical)
		if err != nil {
			// Refusing is the point. Serving a near-miss would let replay report
			// success while the agent saw an answer it never received.
			m.record(logfmt.KindLLMResponseEnd, logfmt.LLMResponseEnd{
				Error: err.Error(), Exchange: exchange,
			})
			return err
		}
		return m.relayRecorded(res, agent, exchange)
	}

	outHeader, outBody := req.Header, body
	if m.cfg.Broker != nil {
		h, b, injections, err := m.cfg.Broker.Inject(host, req.Header, body)
		if err != nil {
			return err
		}
		outHeader, outBody = h, b
		for _, in := range injections {
			m.record(logfmt.KindSecretInjected, logfmt.SecretInjected{
				Ref: in.Ref, Placeholder: in.Placeholder, Host: host, ValueHash: in.ValueHash,
			})
		}
	}

	out := req.Clone(req.Context())
	out.Header = outHeader
	out.Body = io.NopCloser(bytesReader(outBody))
	out.ContentLength = int64(len(outBody))
	out.Host = host
	out.URL.Scheme = "https"
	out.URL.Host = host
	// Connection reuse is the mediator's business, not the agent's.
	out.Header.Del("Connection")

	_ = upstream.SetWriteDeadline(time.Now().Add(forwardTimeout))
	if err := out.Write(upstream); err != nil {
		m.record(logfmt.KindLLMResponseEnd, logfmt.LLMResponseEnd{Error: "sending upstream: " + err.Error()})
		return err
	}

	_ = upstream.SetReadDeadline(time.Now().Add(forwardTimeout))
	resp, err := http.ReadResponse(upstreamReader, out)
	if err != nil {
		m.record(logfmt.KindLLMResponseEnd, logfmt.LLMResponseEnd{Error: "reading the response: " + err.Error()})
		return err
	}

	return m.relayResponse(resp, agent, exchange)
}

// relayRecorded serves a recorded response back to the agent, re-recording it so
// the replayed run produces its own bundle.
//
// Chunk boundaries are reproduced exactly, because agent code branches on
// partial parses -- reassembling and re-splitting differently would change what
// the agent saw even though the bytes matched.
//
// Inter-chunk timing is not reproduced. Sleeping through a recorded four-minute
// run would defeat the point of replay being fast, and nothing in the
// determinism claim depends on wall-clock spacing.
func (m *Mediator) relayRecorded(res *PlaybackResponse, agent net.Conn, exchange uint64) error {
	head := &http.Response{
		StatusCode: res.Status,
		Header:     make(http.Header, len(res.Headers)),
	}
	for k, v := range res.Headers {
		head.Header.Set(k, v)
	}

	// Frame the body by length.
	//
	// The recorded headers describe how the *original* response was framed, and
	// that framing may not survive: an SSE stream arrives chunked with no
	// Content-Length, and replaying those headers verbatim while writing the body
	// raw leaves the client with no way to know where the response ends. It reads
	// until the connection closes, which never happens because the mediator is
	// waiting for the next request on the same connection.
	//
	// Since the whole body is already known, length-delimiting is both correct
	// and simpler. What matters for fidelity is preserved either way: the chunk
	// *arrival boundaries* are reproduced exactly by writing them separately, so
	// a client parsing incrementally still sees the same partial reads it saw
	// when the run was recorded.
	var total int
	for _, c := range res.Chunks {
		total += len(c)
	}
	head.Header.Del("Transfer-Encoding")
	head.Header.Del("Content-Length")
	head.Header.Set("Content-Length", itoa(total))

	if err := writeResponseHead(agent, head); err != nil {
		return err
	}

	var relayErr error
	for i, chunk := range res.Chunks {
		m.record(logfmt.KindLLMResponseChunk, logfmt.LLMResponseChunk{
			Seq: uint32(i), Data: chunk, Exchange: exchange,
		})
		if _, err := agent.Write(chunk); err != nil {
			relayErr = err
			break
		}
	}

	end := logfmt.LLMResponseEnd{
		Status:     res.Status,
		Headers:    res.Headers,
		ChunkCount: uint32(len(res.Chunks)),
		Error:      res.Error,
		Exchange:   exchange,
	}
	if relayErr != nil {
		end.Error = relayErr.Error()
	}
	m.record(logfmt.KindLLMResponseEnd, end)
	return relayErr
}

// relayResponse streams the response back to the agent, recording each chunk as
// it passes.
//
// Chunks are recorded as they are framed on the wire, not after reassembly.
// Agent code branches on partial parses, so the boundaries are themselves a
// source of nondeterminism -- and once the client has reassembled them the
// information is gone and cannot be recovered. This is what W3's replay depends
// on.
func (m *Mediator) relayResponse(resp *http.Response, agent net.Conn, exchange uint64) error {
	defer resp.Body.Close()

	// Let net/http write the response, rather than hand-rolling the head.
	//
	// Framing is the reason. Hand-writing the status line and headers and then
	// streaming the body raw only works when the upstream sent a Content-Length.
	// When it did not -- a chunked response, which is every streaming endpoint --
	// the agent has no way to know where the body ends, so it reads until the
	// connection closes. That never happens, because the mediator is waiting for
	// the next request on the same connection, and the agent times out holding a
	// complete response it cannot see the end of.
	//
	// Response.Write derives the framing from ContentLength and TransferEncoding
	// the way a real server would. Wrapping the body keeps the chunk recording,
	// so nothing is lost by handing off the framing.
	body := &recordingBody{
		inner:    resp.Body,
		mediator: m,
		exchange: exchange,
		lastAt:   time.Now(),
	}
	resp.Body = body

	relayErr := resp.Write(agent)

	end := logfmt.LLMResponseEnd{
		Status:     resp.StatusCode,
		Headers:    flatten(resp.Header),
		ChunkCount: body.chunks,
		Exchange:   exchange,
	}
	if relayErr != nil {
		end.Error = relayErr.Error()
	}
	m.record(logfmt.KindLLMResponseEnd, end)
	return relayErr
}

// recordingBody records each read as it passes through.
//
// Reads are recorded at the boundary they arrive on, before anything
// reassembles them, because agent code branches on partial parses and those
// boundaries are themselves a source of nondeterminism.
type recordingBody struct {
	inner    io.ReadCloser
	mediator *Mediator
	exchange uint64
	chunks   uint32
	lastAt   time.Time
}

func (b *recordingBody) Read(p []byte) (int, error) {
	n, err := b.inner.Read(p)
	if n > 0 {
		now := time.Now()
		chunk := make([]byte, n)
		copy(chunk, p[:n])
		b.mediator.record(logfmt.KindLLMResponseChunk, logfmt.LLMResponseChunk{
			Seq:       b.chunks,
			Data:      chunk,
			SincePrev: now.Sub(b.lastAt).Nanoseconds(),
			Exchange:  b.exchange,
		})
		b.chunks++
		b.lastAt = now
	}
	return n, err
}

func (b *recordingBody) Close() error { return b.inner.Close() }

func writeResponseHead(w io.Writer, resp *http.Response) error {
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode)); err != nil {
		return err
	}
	if err := resp.Header.Write(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

// keyFor derives a request's identity, advancing the run's occurrence counter.
//
// One run can send byte-identical requests and get different answers -- a retry
// after a 429 is the ordinary case -- so the ordinal is part of the identity.
func (m *Mediator) keyFor(canonical []byte) reqkey.Key {
	m.occMu.Lock()
	defer m.occMu.Unlock()
	if m.occurrences == nil {
		m.occurrences = make(map[hashchain.Hash]uint32)
	}
	return reqkey.Derive(canonical, m.occurrences)
}

func flatten(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct {
	b []byte
	i int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
