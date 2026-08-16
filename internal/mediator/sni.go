package mediator

import (
	"errors"
	"fmt"
)

// Server Name Indication parsing.
//
// Because every hostname resolves to the mediator (ADR-0006), the agent opens a
// TLS connection here for whatever host it believes it is reaching, and the
// ClientHello names that host in the clear. That name is how the mediator knows
// what to record and what to check policy against.
//
// This code parses bytes written by the untrusted process. It must never panic
// and never read out of bounds, so every field goes through a bounds-checked
// cursor rather than direct slice indexing. A panic here would take down the
// supervisor -- the component holding the signing key and the audit log -- on
// input the agent fully controls.

var (
	// ErrIncomplete means the ClientHello has not arrived in full yet. The
	// caller should read more and retry rather than treat the connection as bad.
	ErrIncomplete = errors.New("mediator: need more bytes to parse the ClientHello")

	// ErrNotTLS means this is not a TLS handshake at all.
	ErrNotTLS = errors.New("mediator: not a TLS ClientHello")

	// ErrNoSNI means a well-formed ClientHello carried no server_name extension.
	// The connection is still recorded, with an empty host -- see ADR-0006 on
	// literal-IP dials.
	ErrNoSNI = errors.New("mediator: ClientHello carries no server_name extension")
)

const (
	recordHandshake      = 0x16
	handshakeClientHello = 0x01
	extServerName        = 0x0000
	nameTypeHostName     = 0x00

	// MaxClientHello bounds how much the caller should ever buffer looking for
	// one. A TLS record body is capped at 2^14, plus the 5-byte record header.
	MaxClientHello = 1<<14 + 5
)

// ServerName extracts the SNI hostname from a TLS ClientHello.
//
// b should be the first bytes of the connection, obtained with MSG_PEEK or an
// equivalent, so the handshake can still be replayed to the real TLS stack
// afterwards.
func ServerName(b []byte) (string, error) {
	c := &cursor{b: b}

	// TLS record header.
	typ, err := c.u8()
	if err != nil {
		return "", err
	}
	if typ != recordHandshake {
		return "", ErrNotTLS
	}
	if err := c.skip(2); err != nil { // legacy record version
		return "", err
	}
	recLen, err := c.u16()
	if err != nil {
		return "", err
	}
	if recLen == 0 || int(recLen) > 1<<14 {
		return "", fmt.Errorf("%w: implausible record length %d", ErrNotTLS, recLen)
	}
	// If the record has not fully arrived, say so rather than parsing a prefix.
	// A ClientHello split across TCP segments is ordinary, not hostile.
	if len(b) < 5+int(recLen) {
		return "", ErrIncomplete
	}

	// Handshake header.
	hs, err := c.u8()
	if err != nil {
		return "", err
	}
	if hs != handshakeClientHello {
		return "", ErrNotTLS
	}
	if err := c.skip(3); err != nil { // handshake length
		return "", err
	}
	if err := c.skip(2); err != nil { // legacy_version
		return "", err
	}
	if err := c.skip(32); err != nil { // random
		return "", err
	}

	// legacy_session_id
	if err := c.skipVec8(); err != nil {
		return "", err
	}
	// cipher_suites
	if err := c.skipVec16(); err != nil {
		return "", err
	}
	// legacy_compression_methods
	if err := c.skipVec8(); err != nil {
		return "", err
	}

	// Extensions are optional in the grammar; their absence means no SNI.
	extLen, err := c.u16()
	if err != nil {
		if errors.Is(err, ErrIncomplete) {
			return "", ErrNoSNI
		}
		return "", err
	}
	end := c.i + int(extLen)
	if end > len(c.b) {
		return "", ErrIncomplete
	}

	for c.i < end {
		etype, err := c.u16()
		if err != nil {
			return "", err
		}
		elen, err := c.u16()
		if err != nil {
			return "", err
		}
		body, err := c.bytes(int(elen))
		if err != nil {
			return "", err
		}
		if etype == extServerName {
			return parseServerNameList(body)
		}
	}
	return "", ErrNoSNI
}

// parseServerNameList reads the ServerNameList of the server_name extension.
//
// The list is defined as a sequence, but RFC 6066 permits only one entry per
// name type and every real client sends exactly one host_name. The first
// host_name is taken and the rest ignored; a second one would be a way to show
// one name to a policy engine and another to a server, so it is not merged in.
func parseServerNameList(b []byte) (string, error) {
	c := &cursor{b: b}

	listLen, err := c.u16()
	if err != nil {
		return "", err
	}
	if int(listLen) != len(b)-2 {
		return "", fmt.Errorf("%w: server_name list length %d does not match %d bytes", ErrNotTLS, listLen, len(b)-2)
	}

	for c.i < len(c.b) {
		nameType, err := c.u8()
		if err != nil {
			return "", err
		}
		raw, err := c.vec16()
		if err != nil {
			return "", err
		}
		if nameType != nameTypeHostName {
			continue
		}
		name := string(raw)
		if err := validSNI(name); err != nil {
			return "", err
		}
		return name, nil
	}
	return "", ErrNoSNI
}

// validSNI rejects names that should never reach policy evaluation or the event
// log.
//
// A hostile SNI is a string the agent chose, and it ends up in a recorded event
// and in operator-facing output. Control characters could forge log lines;
// non-ASCII has no place here because internationalised names travel as
// punycode on the wire. Rejecting outright is safer than sanitising, since a
// sanitised name might still match a policy rule it should not.
func validSNI(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty server name", ErrNotTLS)
	}
	if len(s) > 253 {
		return fmt.Errorf("%w: server name longer than 253 bytes", ErrNotTLS)
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		case ch == '-' || ch == '.' || ch == '_':
		default:
			return fmt.Errorf("%w: server name contains byte 0x%02x", ErrNotTLS, ch)
		}
	}
	return nil
}

// cursor is a bounds-checked reader over untrusted bytes. Every accessor
// returns ErrIncomplete rather than panicking when the buffer runs out.
type cursor struct {
	b []byte
	i int
}

func (c *cursor) u8() (uint8, error) {
	if c.i+1 > len(c.b) {
		return 0, ErrIncomplete
	}
	v := c.b[c.i]
	c.i++
	return v, nil
}

func (c *cursor) u16() (uint16, error) {
	if c.i+2 > len(c.b) {
		return 0, ErrIncomplete
	}
	v := uint16(c.b[c.i])<<8 | uint16(c.b[c.i+1])
	c.i += 2
	return v, nil
}

func (c *cursor) skip(n int) error {
	if n < 0 || c.i+n > len(c.b) {
		return ErrIncomplete
	}
	c.i += n
	return nil
}

func (c *cursor) bytes(n int) ([]byte, error) {
	if n < 0 || c.i+n > len(c.b) {
		return nil, ErrIncomplete
	}
	v := c.b[c.i : c.i+n]
	c.i += n
	return v, nil
}

// skipVec8 skips a vector with a one-byte length prefix.
func (c *cursor) skipVec8() error {
	n, err := c.u8()
	if err != nil {
		return err
	}
	return c.skip(int(n))
}

// skipVec16 skips a vector with a two-byte length prefix.
func (c *cursor) skipVec16() error {
	n, err := c.u16()
	if err != nil {
		return err
	}
	return c.skip(int(n))
}

// vec16 reads a vector with a two-byte length prefix.
func (c *cursor) vec16() ([]byte, error) {
	n, err := c.u16()
	if err != nil {
		return nil, err
	}
	return c.bytes(int(n))
}
