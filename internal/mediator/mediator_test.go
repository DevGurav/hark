package mediator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevGurav/hark/internal/broker"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/policy"
	"github.com/DevGurav/hark/internal/reqkey"
)

// The mediator binds loopback on high ports in tests, which is what lets the
// whole thing be exercised without a namespace or privilege. In a real run the
// addresses are the veth end and 53/443; nothing else differs.

const allowedHost = "generativelanguage.googleapis.com"

// capture is a Recorder that keeps events in memory.
type capture struct {
	mu     sync.Mutex
	events []captured
	syncs  int
}

type captured struct {
	kind    logfmt.Kind
	payload any
}

func (c *capture) Append(kind logfmt.Kind, payload any) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, captured{kind, payload})
	return uint64(len(c.events) - 1), nil
}

func (c *capture) Sync() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.syncs++
	return nil
}

func (c *capture) kinds() []logfmt.Kind {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]logfmt.Kind, len(c.events))
	for i, e := range c.events {
		out[i] = e.kind
	}
	return out
}

func (c *capture) find(kind logfmt.Kind) []any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []any
	for _, e := range c.events {
		if e.kind == kind {
			out = append(out, e.payload)
		}
	}
	return out
}

func (c *capture) syncCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.syncs
}

func testPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte("allow_hosts = [\""+allowedHost+"\"]\n"), "test.toml")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// start brings up a mediator on loopback and returns it with its recorder.
func start(t *testing.T, cfg Config) (*Mediator, *capture) {
	t.Helper()

	rec := &capture{}
	if cfg.Policy == nil {
		cfg.Policy = testPolicy(t)
	}
	cfg.Recorder = rec
	cfg.BindIP = "127.0.0.1"
	cfg.RunID = "01TESTRUN"
	cfg.Started = make(chan struct{})

	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan struct{})
	go func() { defer close(done); _ = m.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case <-cfg.Started:
	case <-time.After(10 * time.Second):
		t.Fatal("mediator did not start")
	}
	return m, rec
}

func resolverFor(t *testing.T, m *Mediator) *net.Resolver {
	t.Helper()
	addr := m.DNSAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// Every name resolves to the mediator, allowed or not. Refusing here would stop
// the agent connecting, and with it the chance to record an egress attempt
// naming the host it wanted.
func TestDNSResolvesEveryNameToTheMediator(t *testing.T) {
	m, rec := start(t, Config{})
	r := resolverFor(t, m)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, host := range []string{allowedHost, "evil.example"} {
		ips, err := r.LookupHost(ctx, host)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if len(ips) == 0 || ips[0] != "127.0.0.1" {
			t.Fatalf("%s resolved to %v", host, ips)
		}
	}

	queries := rec.find(logfmt.KindDNSQuery)
	if len(queries) < 2 {
		t.Fatalf("expected a DnsQuery per lookup, got %d", len(queries))
	}

	// The decision records what policy says even though the answer is the same.
	var sawAllowed, sawDenied bool
	for _, p := range rec.find(logfmt.KindDNSDecision) {
		d := p.(logfmt.DNSDecision)
		if d.Name == allowedHost && d.Allowed {
			sawAllowed = true
		}
		if d.Name == "evil.example" && !d.Allowed {
			sawDenied = true
		}
	}
	if !sawAllowed || !sawDenied {
		t.Fatalf("policy verdicts not recorded (allowed=%v denied=%v)", sawAllowed, sawDenied)
	}
}

func TestDNSRecordsMalformedQueries(t *testing.T) {
	m, rec := start(t, Config{})

	conn, err := net.Dial("udp", m.DNSAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x00, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range rec.find(logfmt.KindDNSQuery) {
			if p.(logfmt.DNSQuery).Type == "malformed" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a malformed query was not recorded")
}

// The denial path, which is what the incident demo turns on.
func TestDeniedHostIsRefusedAndRecorded(t *testing.T) {
	m, rec := start(t, Config{})

	conn, err := tls.Dial("tcp", m.TLSAddr().String(), &tls.Config{
		ServerName:         "evil.example",
		InsecureSkipVerify: true,
	})
	if err == nil {
		conn.Close()
	}

	waitFor(t, func() bool { return len(rec.find(logfmt.KindEgressDecision)) > 0 })

	attempts := rec.find(logfmt.KindEgressAttempt)
	if len(attempts) == 0 {
		t.Fatal("no EgressAttempt recorded")
	}
	if got := attempts[0].(logfmt.EgressAttempt).Host; got != "evil.example" {
		t.Fatalf("attempt recorded host %q, expected the SNI", got)
	}

	d := rec.find(logfmt.KindEgressDecision)[0].(logfmt.EgressDecision)
	if d.Allowed {
		t.Fatal("a host outside the allowlist was permitted")
	}
	if d.Host != "evil.example" || d.Rule == "" || d.Reason == "" {
		t.Fatalf("denial lacks the detail needed to act on it: %+v", d)
	}

	// A denial is the evidence the bundle exists to carry, so it is forced to
	// disk rather than left in a buffer.
	if rec.syncCount() == 0 {
		t.Fatal("the denial was not synced")
	}
}

// The attempt is written before the decision, so a crash between the two still
// leaves the attempt on the record.
func TestAttemptIsRecordedBeforeDecision(t *testing.T) {
	m, rec := start(t, Config{})

	conn, err := tls.Dial("tcp", m.TLSAddr().String(), &tls.Config{
		ServerName: "evil.example", InsecureSkipVerify: true,
	})
	if err == nil {
		conn.Close()
	}
	waitFor(t, func() bool { return len(rec.find(logfmt.KindEgressDecision)) > 0 })

	kinds := rec.kinds()
	var attemptAt, decisionAt = -1, -1
	for i, k := range kinds {
		if k == logfmt.KindEgressAttempt && attemptAt < 0 {
			attemptAt = i
		}
		if k == logfmt.KindEgressDecision && decisionAt < 0 {
			decisionAt = i
		}
	}
	if attemptAt < 0 || decisionAt < 0 || attemptAt > decisionAt {
		t.Fatalf("attempt must precede decision, got positions %d and %d", attemptAt, decisionAt)
	}
}

// A literal-IP dial carries no SNI. Policy is expressed in names, so it is
// recorded and denied rather than allowed by default.
func TestConnectionWithoutSNIIsDenied(t *testing.T) {
	m, rec := start(t, Config{})

	conn, err := tls.Dial("tcp", m.TLSAddr().String(), &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		conn.Close()
	}
	waitFor(t, func() bool { return len(rec.find(logfmt.KindEgressDecision)) > 0 })

	d := rec.find(logfmt.KindEgressDecision)[0].(logfmt.EgressDecision)
	if d.Allowed {
		t.Fatal("a connection with no server name was permitted")
	}
	if !strings.Contains(d.Reason, "server name") {
		t.Fatalf("reason should explain the missing name: %q", d.Reason)
	}
}

func TestNonTLSConnectionIsRecorded(t *testing.T) {
	m, rec := start(t, Config{})

	conn, err := net.Dial("tcp", m.TLSAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"))
	conn.Close()

	waitFor(t, func() bool { return len(rec.find(logfmt.KindEgressDecision)) > 0 })
	if rec.find(logfmt.KindEgressDecision)[0].(logfmt.EgressDecision).Allowed {
		t.Fatal("a non-TLS connection was permitted")
	}
}

// The allowed path, end to end, against a local upstream.
func TestAllowedHostIsForwardedAndRecorded(t *testing.T) {
	upstream := httpsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "REAL-SECRET") {
			t.Errorf("upstream did not receive the injected credential: %s", body)
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "hello from upstream")
	})

	// This policy needs a secrets mapping, since the broker takes the
	// environment-variable names from it.
	pol, err := policy.Parse([]byte(
		"allow_hosts = [\""+allowedHost+"\"]\n\n[secrets]\napi_key = \"API_KEY\"\n"), "test.toml")
	if err != nil {
		t.Fatal(err)
	}
	br, err := broker.New("01TESTRUN", map[string]string{"api_key": "REAL-SECRET"}, pol)
	if err != nil {
		t.Fatal(err)
	}
	if br.Placeholders()["API_KEY"] == "" {
		t.Fatal("the broker produced no placeholder; the policy is missing its secrets mapping")
	}

	m, rec := start(t, Config{
		Policy: pol,
		Broker: br,
		DialUpstream: func(string) (net.Conn, error) {
			return tls.Dial("tcp", upstream, &tls.Config{InsecureSkipVerify: true})
		},
	})

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(m.CACertPEM()) {
		t.Fatal("could not trust the mediator CA")
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return tls.Dial("tcp", m.TLSAddr().String(), &tls.Config{
					ServerName: allowedHost, RootCAs: pool, NextProtos: []string{"http/1.1"},
				})
			},
		},
		Timeout: 20 * time.Second,
	}

	placeholder := br.Placeholders()["API_KEY"]
	req, err := http.NewRequest("POST", "https://"+allowedHost+"/v1/models",
		strings.NewReader(`{"key":"`+placeholder+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("forwarding failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 || !strings.Contains(string(body), "hello from upstream") {
		t.Fatalf("unexpected response %d: %s", resp.StatusCode, body)
	}

	waitFor(t, func() bool { return len(rec.find(logfmt.KindLLMResponseEnd)) > 0 })

	// The recorded request must hold the placeholder, never the real value.
	reqs := rec.find(logfmt.KindLLMRequest)
	if len(reqs) == 0 {
		t.Fatal("the request was not recorded")
	}
	recorded := reqs[0].(logfmt.LLMRequest)
	if strings.Contains(string(recorded.Body), "REAL-SECRET") {
		t.Fatal("the recorded request contains the real credential")
	}
	if !strings.Contains(string(recorded.Body), placeholder) {
		t.Fatalf("the recorded request lost the placeholder: %s", recorded.Body)
	}
	if recorded.Host != allowedHost || recorded.Method != "POST" {
		t.Fatalf("request recorded wrongly: %+v", recorded)
	}

	// And the substitution itself is on the record, by reference only.
	inj := rec.find(logfmt.KindSecretInjected)
	if len(inj) == 0 {
		t.Fatal("the credential substitution was not recorded")
	}
	if strings.Contains(fmt.Sprint(inj[0]), "REAL-SECRET") {
		t.Fatal("the SecretInjected event carries the real value")
	}

	if len(rec.find(logfmt.KindLLMResponseChunk)) == 0 {
		t.Fatal("no response chunks recorded")
	}
	end := rec.find(logfmt.KindLLMResponseEnd)[0].(logfmt.LLMResponseEnd)
	if end.Status != 200 {
		t.Fatalf("response end recorded status %d", end.Status)
	}
}

// Byte-identical requests must be distinguishable, because a retry after a 429
// is the ordinary case and replay has to tell them apart.
func TestIdenticalRequestsGetDistinctOccurrences(t *testing.T) {
	m := &Mediator{}
	h := http.Header{"Content-Type": []string{"application/json"}}
	body := []byte(`{"a":1}`)

	var first [32]byte
	for i := uint32(0); i < 3; i++ {
		k := m.keyFor(reqkey.Canonicalise("POST", "h", "/p", h, body))
		if k.Occurrence != i {
			t.Fatalf("occurrence %d, expected %d", k.Occurrence, i)
		}
		if i == 0 {
			first = k.Hash
		} else if k.Hash != first {
			t.Fatal("the same request produced different hashes")
		}
	}

	other := m.keyFor(reqkey.Canonicalise("POST", "h", "/other", h, body))
	if other.Occurrence != 0 {
		t.Fatalf("a different path shared an occurrence counter: %d", other.Occurrence)
	}
	if other.Hash == first {
		t.Fatal("a different path produced the same hash")
	}

	// Volatile headers must not split the counter, or a retry would look like a
	// new request and replay would never match it.
	noisy := http.Header{"Content-Type": []string{"application/json"}, "X-Request-Id": []string{"zzz"}}
	if k := m.keyFor(reqkey.Canonicalise("POST", "h", "/p", noisy, body)); k.Occurrence != 3 {
		t.Fatalf("a volatile header started a new counter: occurrence %d", k.Occurrence)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	rec := &capture{}
	p := testPolicy(t)

	for name, cfg := range map[string]Config{
		"nil policy":   {Recorder: rec, BindIP: "127.0.0.1"},
		"nil recorder": {Policy: p, BindIP: "127.0.0.1"},
		"no bind ip":   {Policy: p, Recorder: rec},
		"bad bind ip":  {Policy: p, Recorder: rec, BindIP: "not-an-ip"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatal("accepted an invalid config")
			}
		})
	}
}

// httpsUpstream starts a TLS server standing in for the model endpoint.
func httpsUpstream(t *testing.T, h http.HandlerFunc) string {
	t.Helper()

	ca, err := NewCA("01UPSTREAM")
	if err != nil {
		t.Fatal(err)
	}
	cfg := ca.TLSConfig()
	cfg.NextProtos = []string{"http/1.1"}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the expected events")
}
