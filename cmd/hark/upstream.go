package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// Upstream redirection: -upstream HOST=ADDR.
//
// The mediator normally dials the host the agent asked for. A redirection sends
// that host's traffic somewhere else instead, which is what makes a hermetic
// demo and an honest benchmark possible -- both need a local stub standing in
// for a model endpoint, and benchmarking against a live one would measure
// somebody else's load balancer.
//
// Two things keep it from being a hole. It is recorded in RunStart, so a bundle
// can never quietly claim it reached a host it did not; and a redirected host
// still has to be in the policy allowlist, because the redirection changes
// where the connection goes, not whether it was permitted.

// upstreams is the -upstream flag: a repeatable HOST=ADDR mapping.
type upstreams struct {
	byHost map[string]string
}

func (u *upstreams) String() string { return strings.Join(u.list(), ",") }

func (u *upstreams) Set(v string) error {
	host, addr, ok := strings.Cut(v, "=")
	if !ok || host == "" || addr == "" {
		return fmt.Errorf("expected HOST=ADDR, got %q", v)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("%q: expected HOST=ADDR with a port, e.g. model.example=127.0.0.1:8443", v)
	}
	if u.byHost == nil {
		u.byHost = make(map[string]string)
	}
	u.byHost[strings.ToLower(host)] = addr
	return nil
}

// list renders the mapping for RunStart, sorted so two runs with the same
// redirections produce the same bytes.
func (u *upstreams) list() []string {
	out := make([]string, 0, len(u.byHost))
	for host, addr := range u.byHost {
		out = append(out, host+"="+addr)
	}
	sort.Strings(out)
	return out
}

// setAll replaces the mapping, for a fork inheriting its parent's.
func (u *upstreams) setAll(entries []string) error {
	for _, e := range entries {
		if err := u.Set(e); err != nil {
			return err
		}
	}
	return nil
}

// dialer builds the mediator's DialUpstream, or nil when there is nothing to
// redirect.
//
// caFile, if given, is the only root a redirected connection will accept. A
// stub upstream necessarily presents a certificate no public CA signed, and the
// alternative to naming its CA is skipping verification -- which would silently
// weaken every redirected connection, including ones the operator did not think
// of as a stub.
func (u *upstreams) dialer(caFile string) (func(string) (net.Conn, error), error) {
	if len(u.byHost) == 0 {
		if caFile != "" {
			return nil, fmt.Errorf("-upstream-ca given with no -upstream to use it")
		}
		return nil, nil
	}

	var roots *x509.CertPool
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("-upstream-ca: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("-upstream-ca: %s contains no certificate", caFile)
		}
	}

	byHost := u.byHost
	return func(host string) (net.Conn, error) {
		addr, redirected := byHost[strings.ToLower(host)]
		if !redirected {
			addr = net.JoinHostPort(host, "443")
		}
		cfg := &tls.Config{
			// The name is the one the agent asked for either way. A stub has to
			// hold a certificate for the host it stands in for, which keeps the
			// redirection from also becoming an identity exemption.
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		}
		if redirected {
			cfg.RootCAs = roots
		}
		return tls.Dial("tcp", addr, cfg)
	}, nil
}
