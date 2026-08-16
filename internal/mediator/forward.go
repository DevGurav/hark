package mediator

import (
	"bufio"
	"crypto/tls"
	"errors"
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

	agentReader := bufio.NewReader(agent)
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
	key := m.keyFor(req.Method, host, req.URL.RequestURI(), req.Header, body)
	recorded := logfmt.LLMRequest{
		Host:       host,
		Method:     req.Method,
		Path:       req.URL.RequestURI(),
		Headers:    flatten(req.Header),
		Body:       body,
		RequestKey: key.Hash[:],
		Occurrence: key.Occurrence,
	}
	m.record(logfmt.KindLLMRequest, recorded)

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

	return m.relayResponse(resp, agent)
}

// relayResponse streams the response back to the agent, recording each chunk as
// it passes.
//
// Chunks are recorded as they are framed on the wire, not after reassembly.
// Agent code branches on partial parses, so the boundaries are themselves a
// source of nondeterminism -- and once the client has reassembled them the
// information is gone and cannot be recovered. This is what W3's replay depends
// on.
func (m *Mediator) relayResponse(resp *http.Response, agent net.Conn) error {
	defer resp.Body.Close()

	// Write the status line and headers first, so the agent can start parsing.
	if err := writeResponseHead(agent, resp); err != nil {
		return err
	}

	var (
		seq      uint32
		lastAt   = time.Now()
		buf      = make([]byte, 32*1024)
		relayErr error
	)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			now := time.Now()
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			m.record(logfmt.KindLLMResponseChunk, logfmt.LLMResponseChunk{
				Seq:       seq,
				Data:      chunk,
				SincePrev: now.Sub(lastAt).Nanoseconds(),
			})
			seq++
			lastAt = now

			if _, werr := agent.Write(chunk); werr != nil {
				relayErr = werr
				break
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				relayErr = err
			}
			break
		}
	}

	end := logfmt.LLMResponseEnd{
		Status:     resp.StatusCode,
		Headers:    flatten(resp.Header),
		ChunkCount: seq,
	}
	if relayErr != nil {
		end.Error = relayErr.Error()
	}
	m.record(logfmt.KindLLMResponseEnd, end)
	return relayErr
}

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
func (m *Mediator) keyFor(method, host, path string, h http.Header, body []byte) reqkey.Key {
	canonical := reqkey.Canonicalise(method, host, path, h, body)

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
