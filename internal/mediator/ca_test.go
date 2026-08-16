package mediator

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func newCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA("01TESTRUN")
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// The end-to-end property: a client that trusts only this run's CA completes a
// handshake against the mediator and sees the host it asked for. If this passes,
// interception is transparent to the agent.
func TestClientTrustingTheCAConnectsSuccessfully(t *testing.T) {
	ca := newCA(t)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("CA PEM was not accepted into a cert pool")
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", ca.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, "ok")
			}(c)
		}
	}()

	for _, host := range []string{
		"generativelanguage.googleapis.com",
		"evil.example",
		"api.github.com",
	} {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			RootCAs:    pool,
			ServerName: host,
		})
		if err != nil {
			t.Fatalf("%s: handshake failed: %v", host, err)
		}

		peer := conn.ConnectionState().PeerCertificates[0]
		if err := peer.VerifyHostname(host); err != nil {
			t.Fatalf("%s: served certificate is not valid for the requested host: %v", host, err)
		}
		conn.Close()
	}
}

// A client that does not trust this CA must fail. Interception is meant to be
// invisible to the agent, not to the wider world.
func TestUntrustingClientIsRejected(t *testing.T) {
	ca := newCA(t)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", ca.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	_, err = tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "example.com"})
	if err == nil {
		t.Fatal("a client with default roots accepted the mediator's certificate")
	}
}

func TestCAProperties(t *testing.T) {
	ca := newCA(t)

	block := ca.CertPEM()
	if !strings.Contains(string(block), "BEGIN CERTIFICATE") {
		t.Fatal("CertPEM did not return PEM")
	}
	if strings.Contains(string(block), "PRIVATE KEY") {
		t.Fatal("CertPEM leaked a private key")
	}

	if !ca.cert.IsCA {
		t.Fatal("the CA certificate is not marked as a CA")
	}
	if ca.cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("the CA certificate cannot sign certificates")
	}
	if !ca.cert.MaxPathLenZero {
		t.Fatal("path length is not constrained, so the CA could issue intermediates")
	}
	if !strings.Contains(ca.cert.Subject.CommonName, "01TESTRUN") {
		t.Fatalf("the CA does not name its run: %q", ca.cert.Subject.CommonName)
	}

	// Short-lived by design: a CA that expires with its run cannot be quietly
	// repurposed later.
	if d := time.Until(ca.cert.NotAfter); d > 48*time.Hour {
		t.Fatalf("CA validity of %v is too long", d)
	}
	if !ca.cert.NotBefore.Before(time.Now()) {
		t.Fatal("NotBefore is not backdated for clock skew")
	}
}

// Every run gets its own authority. Two runs must not be able to impersonate
// each other, which is the whole reason the CA is never persisted.
func TestEachRunGetsADistinctCA(t *testing.T) {
	a, err := NewCA("RUN-A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCA("RUN-B")
	if err != nil {
		t.Fatal(err)
	}

	if string(a.CertPEM()) == string(b.CertPEM()) {
		t.Fatal("two runs produced identical CAs")
	}

	leafA, err := a.LeafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leafA.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	poolB := x509.NewCertPool()
	poolB.AppendCertsFromPEM(b.CertPEM())
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: poolB}); err == nil {
		t.Fatal("run B's CA validated a certificate issued by run A")
	}
}

func TestLeafIsCached(t *testing.T) {
	ca := newCA(t)

	first, err := ca.LeafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ca.LeafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("LeafFor re-signed instead of returning the cached certificate")
	}

	other, err := ca.LeafFor("other.example")
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("a different host returned the same certificate")
	}
}

// GetCertificate runs concurrently for every incoming handshake.
func TestLeafForIsConcurrencySafe(t *testing.T) {
	ca := newCA(t)
	hosts := []string{"a.example", "b.example", "c.example", "a.example"}

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := ca.LeafFor(hosts[i%len(hosts)]); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// A literal-IP dial has to land in the IP SAN field, or verification fails.
func TestLeafForIPAddress(t *testing.T) {
	ca := newCA(t)

	leaf, err := ca.LeafFor("10.200.1.1")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.IPAddresses) != 1 || parsed.IPAddresses[0].String() != "10.200.1.1" {
		t.Fatalf("IP did not land in the SAN: %+v", parsed.IPAddresses)
	}
	if len(parsed.DNSNames) != 0 {
		t.Fatal("an IP was also written as a DNS name")
	}
}

// The SNI is agent-controlled, so a hostile name must not become a certificate.
func TestLeafForRejectsHostileNames(t *testing.T) {
	ca := newCA(t)
	for _, host := range []string{
		"example.com\nDENIED",
		"example.com\x00.evil",
		"",
		strings.Repeat("a", 300),
	} {
		if _, err := ca.LeafFor(host); err == nil {
			t.Fatalf("minted a certificate for a hostile name %q", host)
		}
	}
}

func TestNewCARejectsEmptyRunID(t *testing.T) {
	if _, err := NewCA(""); err == nil {
		t.Fatal("accepted an empty run id")
	}
}

// Serial numbers must be positive and not repeat.
func TestSerialsArePositiveAndUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		s, err := randomSerial()
		if err != nil {
			t.Fatal(err)
		}
		if s.Sign() <= 0 {
			t.Fatal("serial is not positive")
		}
		if seen[s.String()] {
			t.Fatal("serial collision")
		}
		seen[s.String()] = true
	}
}

func TestCertPEMIsACopy(t *testing.T) {
	ca := newCA(t)
	got := ca.CertPEM()
	got[0] ^= 0xFF
	if ca.CertPEM()[0] == got[0] {
		t.Fatal("CertPEM handed out its internal buffer")
	}
}
