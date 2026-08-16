package mediator

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// realClientHello produces a genuine ClientHello by driving Go's own TLS stack
// against a connection that captures the first write and then fails.
//
// Testing against a hand-written fixture would only prove the parser agrees with
// my reading of the RFC. Testing against a real stack proves it agrees with what
// clients actually send, which is the thing that matters at runtime.
func realClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	var buf bytes.Buffer
	c := tls.Client(&captureConn{w: &buf}, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	_ = c.Handshake() // fails on read; the ClientHello is already captured
	if buf.Len() == 0 {
		t.Fatal("captured no ClientHello")
	}
	return buf.Bytes()
}

func TestServerNameFromRealClientHello(t *testing.T) {
	for _, want := range []string{
		"example.com",
		"generativelanguage.googleapis.com",
		"evil.example",
		"a.b.c.d.e.f.example",
	} {
		got, err := ServerName(realClientHello(t, want))
		if err != nil {
			t.Fatalf("%s: %v", want, err)
		}
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// A ClientHello arriving in pieces is completely ordinary. Every prefix must
// report ErrIncomplete rather than guessing, erroring differently, or panicking.
func TestTruncationAtEveryPrefix(t *testing.T) {
	full := realClientHello(t, "example.com")

	for i := 0; i < len(full); i++ {
		name, err := ServerName(full[:i])
		if err == nil {
			t.Fatalf("prefix of %d bytes parsed as complete, returning %q", i, name)
		}
		if !errors.Is(err, ErrIncomplete) && !errors.Is(err, ErrNotTLS) {
			t.Fatalf("prefix of %d bytes: unexpected error %v", i, err)
		}
	}

	// And the complete thing still works, so the loop above was not vacuous.
	if _, err := ServerName(full); err != nil {
		t.Fatalf("full ClientHello failed: %v", err)
	}
}

// Every single-byte corruption must be handled, not crash. This is the
// property that matters most: the supervisor holds the signing key and the
// audit log, and these bytes come from the untrusted process.
func TestSingleByteCorruptionNeverPanics(t *testing.T) {
	full := realClientHello(t, "example.com")

	for i := 0; i < len(full); i++ {
		for _, mask := range []byte{0x01, 0x80, 0xFF} {
			b := make([]byte, len(full))
			copy(b, full)
			b[i] ^= mask
			// The result is irrelevant; not panicking is the assertion.
			_, _ = ServerName(b)
		}
	}
}

func TestNotTLS(t *testing.T) {
	for name, b := range map[string][]byte{
		"http":                    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		"ssh":                     []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		"zeroes":                  make([]byte, 64),
		"app data":                {0x17, 0x03, 0x03, 0x00, 0x10},
		"alert":                   {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
		"handshake but not hello": {0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ServerName(b); err == nil {
				t.Fatal("non-TLS input parsed as a ClientHello")
			}
		})
	}
}

// A client dialling a literal IP sends no SNI. That is a legitimate case which
// must be distinguishable from a parse failure, because it is still recorded as
// an attempt -- just with an empty host.
func TestNoSNIIsItsOwnOutcome(t *testing.T) {
	var buf bytes.Buffer
	c := tls.Client(&captureConn{w: &buf}, &tls.Config{InsecureSkipVerify: true})
	_ = c.Handshake()

	_, err := ServerName(buf.Bytes())
	if !errors.Is(err, ErrNoSNI) {
		t.Fatalf("expected ErrNoSNI for a ClientHello without SNI, got %v", err)
	}
}

// A name the agent chose ends up in a recorded event and in operator-facing
// output. Control characters could forge log lines, so they are refused rather
// than sanitised -- a cleaned-up name might still match a rule it should not.
func TestHostileServerNamesRejected(t *testing.T) {
	for name, host := range map[string]string{
		"newline":    "example.com\nDENIED: nothing to see here",
		"nul":        "example.com\x00.evil.example",
		"cr":         "example.com\r\n",
		"tab":        "example\t.com",
		"non-ascii":  "exámple.com",
		"escape":     "example.com\x1b[2K",
		"whitespace": "example.com ",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validSNI(host); err == nil {
				t.Fatalf("accepted a hostile server name: %q", host)
			}
		})
	}

	for _, ok := range []string{
		"example.com",
		"a-b.example.com",
		"xn--exmple-cua.com", // punycode: how IDNs actually travel
		"localhost",
	} {
		if err := validSNI(ok); err != nil {
			t.Fatalf("rejected a legitimate name %q: %v", ok, err)
		}
	}
}

func TestImplausibleRecordLength(t *testing.T) {
	// Handshake record claiming a body larger than TLS permits.
	b := []byte{0x16, 0x03, 0x01, 0xFF, 0xFF, 0x01}
	if _, err := ServerName(b); !errors.Is(err, ErrNotTLS) {
		t.Fatalf("expected ErrNotTLS for an oversized record, got %v", err)
	}
}

func TestEmptyInput(t *testing.T) {
	if _, err := ServerName(nil); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("expected ErrIncomplete for empty input, got %v", err)
	}
}

// FuzzServerName asserts one property: arbitrary bytes never panic. Run longer
// with: go test ./internal/mediator -fuzz=FuzzServerName
func FuzzServerName(f *testing.F) {
	f.Add(realClientHello(&testing.T{}, "example.com"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		name, err := ServerName(b)
		// If it claims success, the name must be one we would accept, otherwise
		// something unvalidated escaped the parser.
		if err == nil {
			if vErr := validSNI(name); vErr != nil {
				t.Fatalf("returned an invalid name %q: %v", name, vErr)
			}
		}
	})
}

// captureConn is a net.Conn that records writes and refuses reads.
type captureConn struct{ w io.Writer }

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Write(b []byte) (int, error)      { return c.w.Write(b) }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }
