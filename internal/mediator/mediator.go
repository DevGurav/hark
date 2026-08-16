package mediator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/DevGurav/hark/internal/broker"
	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/policy"
)

// The mediator is the only thing the agent can reach, and it is both the
// enforcement point and the recorder. That identity is the project's central
// design claim: one artifact ends up being the security record and a sufficient
// input to re-derive the run, because the same component produced both.
//
// It listens on two ports of the veth address:
//
//	:53   every name the agent resolves
//	:443  every connection it opens, since every name resolves here
//
// See ADR-0006 for why DNS is mediated rather than forwarded.

// Recorder is the mediator's view of the event log.
//
// An interface rather than the bundle writer directly, so the mediator can be
// tested without a file on disk -- and because this is the seam W3's playback
// mode replaces.
type Recorder interface {
	Append(kind logfmt.Kind, payload any) (uint64, error)
	Sync() error
}

// Config describes one mediator.
type Config struct {
	Policy   *policy.Policy
	Broker   *broker.Broker
	Recorder Recorder

	// BindIP is the veth address in a real run. Tests use loopback, which is
	// what lets everything below be exercised without a namespace.
	BindIP string

	// DNSPort and TLSPort are 53 and 443 in a real run. Tests use high ports so
	// they need no privilege.
	DNSPort int
	TLSPort int

	RunID string

	// Started is closed once both listeners are accepting. Tests wait on it
	// instead of sleeping.
	Started chan struct{}

	// DialUpstream overrides how an allowed host is reached. Nil means a real
	// TLS dial to host:443.
	//
	// The seam exists so the forwarding path can be exercised against a local
	// server. Testing it only against live endpoints would make the suite
	// depend on the internet and on somebody else's uptime.
	DialUpstream func(host string) (net.Conn, error)
}

// Mediator terminates the agent's traffic.
type Mediator struct {
	cfg Config
	ca  *CA

	dns net.PacketConn
	tls net.Listener

	// mu serialises recording. Concurrent connections are ordered here and
	// nowhere else, which is what gives the log a total order over boundary
	// crossings -- and what replay follows. It deliberately does not extend to
	// anything inside the agent; see docs/architecture.md on concurrency.
	mu sync.Mutex

	// occurrences counts byte-identical requests, so replay can tell a retry
	// apart from the call it repeats. Separate from mu because it is taken
	// inside the request path, not around recording.
	occMu       sync.Mutex
	occurrences map[hashchain.Hash]uint32

	closeOnce sync.Once
	startOnce sync.Once
}

// New builds a mediator. It does not listen until Serve is called.
func New(cfg Config) (*Mediator, error) {
	if cfg.Policy == nil {
		return nil, errors.New("mediator: nil policy")
	}
	if cfg.Recorder == nil {
		return nil, errors.New("mediator: nil recorder")
	}
	if cfg.BindIP == "" {
		return nil, errors.New("mediator: no bind address")
	}
	if net.ParseIP(cfg.BindIP) == nil {
		return nil, fmt.Errorf("mediator: %q is not an IP address", cfg.BindIP)
	}

	ca, err := NewCA(cfg.RunID)
	if err != nil {
		return nil, err
	}
	return &Mediator{cfg: cfg, ca: ca}, nil
}

// CACertPEM returns the certificate the agent must trust.
func (m *Mediator) CACertPEM() []byte { return m.ca.CertPEM() }

// DNSAddr and TLSAddr report the bound addresses, which tests need when they
// asked for port 0.
func (m *Mediator) DNSAddr() net.Addr {
	if m.dns == nil {
		return nil
	}
	return m.dns.LocalAddr()
}

func (m *Mediator) TLSAddr() net.Addr {
	if m.tls == nil {
		return nil
	}
	return m.tls.Addr()
}

// Serve runs both listeners until ctx is cancelled.
func (m *Mediator) Serve(ctx context.Context) error {
	var err error
	m.dns, err = net.ListenPacket("udp", net.JoinHostPort(m.cfg.BindIP, itoa(m.cfg.DNSPort)))
	if err != nil {
		return fmt.Errorf("mediator: listening for DNS: %w", err)
	}
	m.tls, err = net.Listen("tcp", net.JoinHostPort(m.cfg.BindIP, itoa(m.cfg.TLSPort)))
	if err != nil {
		m.dns.Close()
		return fmt.Errorf("mediator: listening for TLS: %w", err)
	}

	m.startOnce.Do(func() {
		if m.cfg.Started != nil {
			close(m.cfg.Started)
		}
	})

	go func() {
		<-ctx.Done()
		m.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); m.serveDNS() }()
	go func() { defer wg.Done(); m.serveTLS() }()
	wg.Wait()
	return nil
}

// Close stops both listeners. Safe to call more than once.
func (m *Mediator) Close() error {
	m.closeOnce.Do(func() {
		if m.dns != nil {
			m.dns.Close()
		}
		if m.tls != nil {
			m.tls.Close()
		}
	})
	return nil
}

// record appends one event under the ordering lock.
func (m *Mediator) record(kind logfmt.Kind, payload any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = m.cfg.Recorder.Append(kind, payload)
}

// recordDenial appends the pair and forces it to disk.
//
// A denial is the evidence the bundle exists to carry. A crash immediately
// afterwards must not be able to erase it, so this is the one path that syncs.
func (m *Mediator) recordDenial(attempt logfmt.Kind, attemptPayload any, decision logfmt.Kind, decisionPayload any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = m.cfg.Recorder.Append(attempt, attemptPayload)
	_, _ = m.cfg.Recorder.Append(decision, decisionPayload)
	_ = m.cfg.Recorder.Sync()
}

// ---------- DNS ----------

func (m *Mediator) serveDNS() {
	buf := make([]byte, 512)
	for {
		n, addr, err := m.dns.ReadFrom(buf)
		if err != nil {
			return // listener closed
		}
		resp := m.answerDNS(buf[:n])
		if resp != nil {
			_, _ = m.dns.WriteTo(resp, addr)
		}
	}
}

// answerDNS records the lookup and builds the reply.
//
// Every A query is answered with the mediator's own address, whether policy
// allows the name or not. Refusing here would stop the agent connecting, and
// with it the chance to record an egress attempt naming the host it wanted. The
// decision is still recorded, and enforcement happens at connect time.
func (m *Mediator) answerDNS(raw []byte) []byte {
	q, err := ParseQuery(raw)
	if err != nil {
		// A query too malformed to answer is still an attempt, and worth a line
		// in the log. There is no name to record, so the type carries the reason.
		m.record(logfmt.KindDNSQuery, logfmt.DNSQuery{Type: "malformed"})
		return nil
	}

	m.record(logfmt.KindDNSQuery, logfmt.DNSQuery{
		Name:  q.Question.Name,
		Type:  TypeName(q.Question.Type),
		RawTy: q.Question.Type,
	})

	rule, allowed := m.cfg.Policy.AllowsHost(q.Question.Name)
	reason := "not in the policy allowlist"
	if allowed {
		reason = "allowed by policy"
	}

	if q.Question.Type != TypeA {
		// NOERROR with no answers, so the client falls back to A and still
		// reaches us. NXDOMAIN would end the lookup here.
		m.record(logfmt.KindDNSDecision, logfmt.DNSDecision{
			Name: q.Question.Name, Allowed: allowed, Rule: rule,
			Answer: "", Reason: "no record of this type; client will retry with A",
		})
		return q.AnswerEmpty()
	}

	resp, err := q.AnswerA(net.ParseIP(m.cfg.BindIP), 30)
	if err != nil {
		return q.AnswerRefused()
	}
	m.record(logfmt.KindDNSDecision, logfmt.DNSDecision{
		Name: q.Question.Name, Allowed: allowed, Rule: rule,
		Answer: m.cfg.BindIP, Reason: reason,
	})
	return resp
}

// ---------- TLS ----------

func (m *Mediator) serveTLS() {
	for {
		conn, err := m.tls.Accept()
		if err != nil {
			return // listener closed
		}
		go m.handleConn(conn)
	}
}

// handleConn recovers the intended host from the ClientHello, records the
// attempt, and applies policy.
func (m *Mediator) handleConn(conn net.Conn) {
	defer conn.Close()

	// A stalled handshake must not hold a goroutine forever; an agent could open
	// connections and never speak.
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	host, peeked, err := peekServerName(conn)
	if err != nil && !errors.Is(err, ErrNoSNI) {
		// Not TLS, or never completed. Still an attempt at leaving.
		m.recordDenial(
			logfmt.KindEgressAttempt, logfmt.EgressAttempt{Port: m.cfg.TLSPort, Protocol: "tcp"},
			logfmt.KindEgressDecision, logfmt.EgressDecision{
				Allowed: false, Rule: "sni", Reason: "could not determine the intended host: " + err.Error(),
			})
		return
	}

	attempt := logfmt.EgressAttempt{
		Host: host, Port: m.cfg.TLSPort, Protocol: "tcp", SNI: host,
	}

	// No SNI means a literal-IP dial. Recorded with an empty host and denied,
	// rather than allowed by default -- policy is expressed in names, so a
	// connection carrying none cannot match it.
	if host == "" {
		m.recordDenial(
			logfmt.KindEgressAttempt, attempt,
			logfmt.KindEgressDecision, logfmt.EgressDecision{
				Allowed: false, Rule: "sni",
				Reason: "no server name; policy is expressed in host names",
			})
		return
	}

	rule, allowed := m.cfg.Policy.AllowsHost(host)
	if !allowed {
		m.recordDenial(
			logfmt.KindEgressAttempt, attempt,
			logfmt.KindEgressDecision, logfmt.EgressDecision{
				Host: host, Allowed: false, Rule: "allow_hosts",
				Reason: "host not in the policy allowlist",
			})
		return
	}

	m.record(logfmt.KindEgressAttempt, attempt)
	m.record(logfmt.KindEgressDecision, logfmt.EgressDecision{
		Host: host, Allowed: true, Rule: rule, Reason: "allowed by policy",
	})

	_ = conn.SetReadDeadline(time.Time{})
	m.forward(&peekedConn{Conn: conn, pending: peeked}, host)
}

// peekServerName reads enough of the connection to find the SNI, returning the
// bytes consumed so they can be replayed into the TLS stack afterwards.
func peekServerName(conn net.Conn) (string, []byte, error) {
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 1024)

	for len(buf) < MaxClientHello {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			host, sniErr := ServerName(buf)
			if sniErr == nil {
				return host, buf, nil
			}
			if !errors.Is(sniErr, ErrIncomplete) {
				return "", buf, sniErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", buf, fmt.Errorf("connection closed before the handshake completed")
			}
			return "", buf, err
		}
	}
	return "", buf, fmt.Errorf("no ClientHello within %d bytes", MaxClientHello)
}

// peekedConn replays already-read bytes before continuing with the connection,
// so the TLS server sees a handshake that looks untouched.
type peekedConn struct {
	net.Conn
	pending []byte
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
