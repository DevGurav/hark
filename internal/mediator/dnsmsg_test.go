package mediator

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// buildQuery assembles a query by hand, for the cases a real resolver will not
// produce.
func buildQuery(t *testing.T, id uint16, name string, qtype uint16) []byte {
	t.Helper()

	out := make([]byte, 0, 64)
	out = binary.BigEndian.AppendUint16(out, id)
	out = binary.BigEndian.AppendUint16(out, flagRecursionDesired)
	out = binary.BigEndian.AppendUint16(out, 1) // QDCOUNT
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)

	if name != "" {
		for _, label := range strings.Split(name, ".") {
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
	}
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, qtype)
	out = binary.BigEndian.AppendUint16(out, ClassINET)
	return out
}

// serve runs the resolver logic on a loopback UDP socket and returns its
// address. It is the same decision the mediator makes: A queries resolve to us,
// everything else gets NOERROR with no answers.
func serve(t *testing.T, answer net.IP) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := ParseQuery(buf[:n])
			if err != nil {
				continue
			}
			var resp []byte
			if q.Question.Type == TypeA {
				resp, err = q.AnswerA(answer, 30)
				if err != nil {
					continue
				}
			} else {
				resp = q.AnswerEmpty()
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

// The end-to-end check: Go's own resolver sends real queries and parses our
// responses. Hand-built fixtures would only prove the code agrees with my
// reading of RFC 1035; this proves it agrees with a real client.
func TestAgainstGoResolver(t *testing.T) {
	addr := serve(t, net.IPv4(10, 200, 1, 1))

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, host := range []string{
		"example.com",
		"generativelanguage.googleapis.com",
		"evil.example",
		"a-b.c.d.example",
	} {
		ips, err := r.LookupHost(ctx, host)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		var found bool
		for _, ip := range ips {
			if ip == "10.200.1.1" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s resolved to %v, expected the mediator address", host, ips)
		}
	}
}

// AAAA must return NOERROR with no answers so the client falls back to A and
// still reaches the mediator. NXDOMAIN would convince it the name does not
// exist and it would give up without ever connecting.
func TestAAAAFallsBackToA(t *testing.T) {
	q, err := ParseQuery(buildQuery(t, 0x1234, "example.com", TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}

	resp := q.AnswerEmpty()
	if len(resp) < headerLen {
		t.Fatal("response is shorter than a header")
	}
	if rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000F; rcode != RcodeSuccess {
		t.Fatalf("rcode %d, expected NOERROR so the client retries with A", rcode)
	}
	if an := binary.BigEndian.Uint16(resp[6:8]); an != 0 {
		t.Fatalf("expected 0 answers, got %d", an)
	}
}

func TestParseQuestion(t *testing.T) {
	q, err := ParseQuery(buildQuery(t, 0xBEEF, "Api.GitHub.com", TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if q.ID != 0xBEEF {
		t.Fatalf("id %#x", q.ID)
	}
	// Lower-cased at parse time, so policy comparison never has to think about it.
	if q.Question.Name != "api.github.com" {
		t.Fatalf("name %q", q.Question.Name)
	}
	if q.Question.Type != TypeA || q.Question.Class != ClassINET {
		t.Fatalf("type/class %d/%d", q.Question.Type, q.Question.Class)
	}
}

func TestResponseEchoesID(t *testing.T) {
	q, err := ParseQuery(buildQuery(t, 0x0F0F, "example.com", TypeA))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := q.AnswerA(net.IPv4(10, 0, 0, 1), 30)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x0F0F {
		t.Fatal("response does not echo the query id, so the client will discard it")
	}
	if binary.BigEndian.Uint16(resp[2:4])&flagResponse == 0 {
		t.Fatal("QR bit not set, so the response looks like a query")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatal("expected exactly one answer")
	}
}

// A pointer loop is the classic way to hang a naive resolver. Hanging here would
// stall the run the supervisor is recording.
func TestCompressionPointerLoopIsBounded(t *testing.T) {
	msg := make([]byte, headerLen)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	// A name at offset 12 that points at itself.
	msg = append(msg, 0xC0, byte(headerLen))
	msg = binary.BigEndian.AppendUint16(msg, TypeA)
	msg = binary.BigEndian.AppendUint16(msg, ClassINET)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := ParseQuery(msg); err == nil {
			t.Error("a self-referential compression pointer parsed successfully")
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("parsing a pointer loop did not terminate")
	}
}

func TestMalformedQueries(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"header only":      make([]byte, headerLen),
		"short header":     {0x00, 0x01, 0x02},
		"label runs past":  append(append(make([]byte, headerLen), 0x40), 'a'),
		"no type or class": append(append(make([]byte, headerLen), 3, 'a', 'b', 'c'), 0),
	}
	// Give the header-bearing cases a QDCOUNT of 1 so they fail on the question,
	// not on the count.
	for name, msg := range cases {
		if len(msg) >= headerLen {
			binary.BigEndian.PutUint16(msg[4:6], 1)
		}
		t.Run(name, func(t *testing.T) {
			if _, err := ParseQuery(msg); err == nil {
				t.Fatal("malformed message parsed successfully")
			}
		})
	}
}

func TestUnsupportedQueries(t *testing.T) {
	// A response, not a query.
	resp := buildQuery(t, 1, "example.com", TypeA)
	binary.BigEndian.PutUint16(resp[2:4], flagResponse)
	if _, err := ParseQuery(resp); !errors.Is(err, ErrUnsupportedQuery) {
		t.Fatalf("expected ErrUnsupportedQuery for a response, got %v", err)
	}

	// Two questions.
	two := buildQuery(t, 1, "example.com", TypeA)
	binary.BigEndian.PutUint16(two[4:6], 2)
	if _, err := ParseQuery(two); !errors.Is(err, ErrUnsupportedQuery) {
		t.Fatalf("expected ErrUnsupportedQuery for a multi-question message, got %v", err)
	}
}

// The queried name is agent-chosen and lands in an event and in operator output,
// so control characters must not survive parsing.
func TestHostileNamesRejected(t *testing.T) {
	for name, label := range map[string]string{
		"newline": "exa\nmple",
		"nul":     "exa\x00mple",
		"escape":  "exa\x1b[2Kmple",
		"space":   "exa mple",
	} {
		t.Run(name, func(t *testing.T) {
			msg := make([]byte, headerLen)
			binary.BigEndian.PutUint16(msg[4:6], 1)
			msg = append(msg, byte(len(label)))
			msg = append(msg, label...)
			msg = append(msg, 0)
			msg = binary.BigEndian.AppendUint16(msg, TypeA)
			msg = binary.BigEndian.AppendUint16(msg, ClassINET)

			if _, err := ParseQuery(msg); err == nil {
				t.Fatalf("accepted a hostile name containing %q", label)
			}
		})
	}
}

func TestOversizedLabelAndName(t *testing.T) {
	// A label longer than 63 bytes.
	msg := make([]byte, headerLen)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, 64)
	msg = append(msg, strings.Repeat("a", 64)...)
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, TypeA)
	msg = binary.BigEndian.AppendUint16(msg, ClassINET)
	if _, err := ParseQuery(msg); err == nil {
		t.Fatal("accepted a label longer than 63 bytes")
	}

	// A name longer than 253 bytes, built from legal labels.
	long := make([]byte, headerLen)
	binary.BigEndian.PutUint16(long[4:6], 1)
	for i := 0; i < 10; i++ {
		long = append(long, 60)
		long = append(long, strings.Repeat("b", 60)...)
	}
	long = append(long, 0)
	long = binary.BigEndian.AppendUint16(long, TypeA)
	long = binary.BigEndian.AppendUint16(long, ClassINET)
	if _, err := ParseQuery(long); err == nil {
		t.Fatal("accepted a name longer than 253 bytes")
	}
}

func TestAnswerARejectsIPv6(t *testing.T) {
	q, err := ParseQuery(buildQuery(t, 1, "example.com", TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.AnswerA(net.ParseIP("2001:db8::1"), 30); err == nil {
		t.Fatal("built an A record from an IPv6 address")
	}
}

func TestTypeName(t *testing.T) {
	if TypeName(TypeA) != "A" || TypeName(TypeAAAA) != "AAAA" {
		t.Fatal("well-known types render wrongly")
	}
	if TypeName(9999) != "TYPE9999" {
		t.Fatalf("unknown type rendered as %q", TypeName(9999))
	}
}

// Arbitrary bytes must never panic. The agent chooses every one of them.
func FuzzParseQuery(f *testing.F) {
	f.Add(buildQuery(&testing.T{}, 1, "example.com", TypeA))
	f.Add(buildQuery(&testing.T{}, 2, "a.b.c", TypeAAAA))
	f.Add(make([]byte, headerLen))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := ParseQuery(b)
		if err != nil {
			return
		}
		// Anything that parsed must also be safe to answer, and the name must be
		// one we would accept -- otherwise unvalidated bytes escaped the parser.
		if vErr := validQueryName(q.Question.Name); vErr != nil {
			t.Fatalf("parsed an invalid name %q: %v", q.Question.Name, vErr)
		}
		_ = q.AnswerEmpty()
		_, _ = q.AnswerA(net.IPv4(10, 0, 0, 1), 30)
	})
}
