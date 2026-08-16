package mediator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// Per-run certificate authority.
//
// The mediator terminates TLS, so it needs a certificate the agent will accept
// for whatever host the agent is trying to reach. It mints one, from a CA
// generated fresh for this run and held only in memory.
//
// Never persisted and never reused across runs, for two reasons. A CA on disk is
// a CA that can be stolen, and one that outlives its run can forge certificates
// for any host long after the run it was created for has ended. Regenerating
// costs a few milliseconds; the alternative costs a standing risk.

const (
	// caValidity bounds the CA's life. Runs are short. A certificate authority
	// that expires the same day cannot be quietly repurposed a month later.
	caValidity = 24 * time.Hour

	// clockSkew backdates NotBefore, because the agent's view of the time may
	// differ slightly from the supervisor's.
	clockSkew = 1 * time.Hour
)

// CA mints leaf certificates for the mediator.
type CA struct {
	runID string
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	pem   []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// NewCA generates a certificate authority for one run.
func NewCA(runID string) (*CA, error) {
	if runID == "" {
		return nil, errors.New("mediator: empty run id")
	}

	// P-256 rather than RSA: key generation is effectively instant, which matters
	// because this happens on every single run, and there is no compatibility
	// reason to prefer RSA for clients we control the trust store of.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mediator: generating CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			// Naming the run makes it obvious in a certificate viewer which run a
			// certificate belongs to, and makes two runs impossible to confuse.
			CommonName:   "hark run " + runID,
			Organization: []string{"hark"},
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mediator: creating CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mediator: parsing CA certificate: %w", err)
	}

	return &CA{
		runID:  runID,
		cert:   cert,
		key:    key,
		pem:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves: make(map[string]*tls.Certificate),
	}, nil
}

// CertPEM returns the CA certificate for installing in the agent's trust store.
// Only the certificate is ever exposed; the private key has no accessor and
// never leaves this struct.
func (c *CA) CertPEM() []byte {
	out := make([]byte, len(c.pem))
	copy(out, c.pem)
	return out
}

// LeafFor returns a certificate valid for host, minting and caching one on first
// use.
//
// Caching matters more than it looks: an agent may open many connections to the
// same host, and signing per connection would add measurable latency to exactly
// the path the overhead benchmark measures.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	if err := validSNI(host); err != nil {
		// Hosts arrive from the SNI the agent chose. Refuse anything that would
		// not have passed policy anyway, rather than minting a certificate for a
		// name containing control characters.
		if ip := net.ParseIP(host); ip == nil {
			return nil, fmt.Errorf("mediator: refusing to mint a certificate for %q: %w", host, err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if leaf, ok := c.leaves[host]; ok {
		return leaf, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mediator: generating leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// A literal-IP dial produces an SNI-less connection or an address; either way
	// the name has to land in the right SAN field or verification fails.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("mediator: signing leaf for %q: %w", host, err)
	}

	leaf := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
	}
	c.leaves[host] = leaf
	return leaf, nil
}

// TLSConfig returns a server config that mints certificates on demand from the
// SNI in each incoming handshake.
func (c *CA) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				// No SNI: the agent dialled an address. Fall back to the local
				// address it connected to so the handshake can still complete and
				// the attempt gets recorded rather than dropped.
				if addr, ok := hello.Conn.LocalAddr().(*net.TCPAddr); ok {
					host = addr.IP.String()
				} else {
					return nil, errors.New("mediator: no SNI and no usable local address")
				}
			}
			return c.LeafFor(host)
		},
	}
}

// randomSerial produces a serial number. x509 requires a positive integer, and
// randomness avoids two certificates from the same CA ever colliding.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("mediator: generating serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}
