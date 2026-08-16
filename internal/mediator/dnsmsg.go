package mediator

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// DNS message parsing and response building.
//
// The mediator is the namespace's only resolver (ADR-0006), so every name the
// agent looks up arrives here. That makes DNS both a control point and a record:
// the query names the destination before any TCP connection exists, and it
// closes DNS off as an exfiltration channel, which an ordinary resolver in the
// namespace would leave wide open.
//
// These bytes come from the untrusted process, so parsing is bounds-checked
// throughout and name compression is explicitly bounded. A pointer loop in a
// crafted query is the classic way to hang a naive resolver, and hanging the
// supervisor would stall the run it is recording.

// Record types and classes, from RFC 1035.
const (
	TypeA     = 1
	TypeCNAME = 5
	TypeAAAA  = 28

	ClassINET = 1
)

// Response codes.
const (
	RcodeSuccess  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeRefused  = 5
)

const (
	headerLen = 12

	flagResponse           = 1 << 15 // QR
	flagRecursionDesired   = 1 << 8  // RD
	flagRecursionAvailable = 1 << 7  // RA

	// maxPointerJumps bounds name-compression following. Sixteen is far more
	// than any legitimate message needs and stops a crafted pointer loop from
	// spinning forever.
	maxPointerJumps = 16

	maxLabelLen = 63
	maxNameLen  = 253
)

var (
	// ErrMalformedDNS means the message could not be parsed.
	ErrMalformedDNS = errors.New("dns: malformed message")

	// ErrUnsupportedQuery means the message parsed but is not something the
	// mediator answers -- a response rather than a query, or a multi-question
	// message. Distinct from malformed because it is worth recording differently.
	ErrUnsupportedQuery = errors.New("dns: unsupported query")
)

// Question is the single question from a query.
type Question struct {
	Name  string // lower-case, no trailing dot
	Type  uint16
	Class uint16
}

// Query is a parsed DNS query.
type Query struct {
	ID       uint16
	Flags    uint16
	Question Question

	// question holds the raw question-section bytes so the response can echo
	// them back verbatim. Re-encoding the name instead would risk answering a
	// subtly different question than was asked.
	question []byte
}

// ParseQuery reads a DNS query.
func ParseQuery(b []byte) (*Query, error) {
	if len(b) < headerLen {
		return nil, fmt.Errorf("%w: %d bytes is shorter than a header", ErrMalformedDNS, len(b))
	}

	q := &Query{
		ID:    binary.BigEndian.Uint16(b[0:2]),
		Flags: binary.BigEndian.Uint16(b[2:4]),
	}
	qdcount := binary.BigEndian.Uint16(b[4:6])

	if q.Flags&flagResponse != 0 {
		return nil, fmt.Errorf("%w: message is a response, not a query", ErrUnsupportedQuery)
	}
	// Exactly one question. Multi-question messages are permitted by the grammar
	// and supported by essentially nothing, so answering them is not worth the
	// ambiguity about which name the policy decision applies to.
	if qdcount != 1 {
		return nil, fmt.Errorf("%w: %d questions, expected exactly 1", ErrUnsupportedQuery, qdcount)
	}

	name, next, err := parseName(b, headerLen)
	if err != nil {
		return nil, err
	}
	if next+4 > len(b) {
		return nil, fmt.Errorf("%w: question truncated before type and class", ErrMalformedDNS)
	}

	q.Question = Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(b[next : next+2]),
		Class: binary.BigEndian.Uint16(b[next+2 : next+4]),
	}
	q.question = append([]byte(nil), b[headerLen:next+4]...)
	return q, nil
}

// parseName decodes a domain name, following compression pointers.
//
// It returns the name and the offset just past the name *in the original
// position* -- following a pointer must not move where the caller continues
// reading, which is the subtle part of compression and an easy place to
// introduce a parser that reads the type and class from the wrong offset.
func parseName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	var (
		jumps int
		next  = -1
		cur   = off
	)

	for {
		if cur >= len(b) {
			return "", 0, fmt.Errorf("%w: name runs past the end of the message", ErrMalformedDNS)
		}
		length := int(b[cur])

		if length == 0 {
			cur++
			if next < 0 {
				next = cur
			}
			break
		}

		if length&0xC0 == 0xC0 {
			if cur+1 >= len(b) {
				return "", 0, fmt.Errorf("%w: truncated compression pointer", ErrMalformedDNS)
			}
			target := int(b[cur]&0x3F)<<8 | int(b[cur+1])
			if next < 0 {
				next = cur + 2
			}
			jumps++
			if jumps > maxPointerJumps {
				return "", 0, fmt.Errorf("%w: compression pointer loop", ErrMalformedDNS)
			}
			if target >= len(b) || target == cur {
				return "", 0, fmt.Errorf("%w: compression pointer out of range", ErrMalformedDNS)
			}
			cur = target
			continue
		}

		if length > maxLabelLen {
			return "", 0, fmt.Errorf("%w: label of %d bytes exceeds 63", ErrMalformedDNS, length)
		}
		cur++
		if cur+length > len(b) {
			return "", 0, fmt.Errorf("%w: label runs past the end of the message", ErrMalformedDNS)
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(b[cur : cur+length])
		cur += length

		if sb.Len() > maxNameLen {
			return "", 0, fmt.Errorf("%w: name longer than %d bytes", ErrMalformedDNS, maxNameLen)
		}
	}

	name := strings.ToLower(sb.String())
	if err := validQueryName(name); err != nil {
		return "", 0, err
	}
	return name, next, nil
}

// validQueryName rejects names that should not reach policy evaluation or the
// event log.
//
// The name is chosen by the agent and ends up in a recorded event and in
// operator-facing output, so a name carrying control characters could forge log
// lines. Refusing is safer than sanitising: a cleaned-up name might still match
// an allowlist entry it should not.
//
// The root query (empty name) is allowed through -- it is meaningless here but
// harmless, and rejecting it would turn an ordinary probe into a parse failure.
func validQueryName(name string) error {
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
		case ch == '-' || ch == '.' || ch == '_':
		default:
			return fmt.Errorf("%w: name contains byte 0x%02x", ErrMalformedDNS, ch)
		}
	}
	return nil
}

// AnswerA builds a response resolving the question to ip.
//
// Every A query is answered with the mediator's own address, allowed or not.
// Refusing at the DNS layer would stop the agent connecting, and with it the
// chance to observe the SNI and record a proper egress attempt. Policy is
// enforced at connect time, where the denial can be recorded with the host it
// was for. See ADR-0006.
func (q *Query) AnswerA(ip net.IP, ttl uint32) ([]byte, error) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("dns: %v is not an IPv4 address", ip)
	}

	out := q.header(RcodeSuccess, 1)
	out = append(out, q.question...)

	// Point the answer's name at the question's, rather than repeating it. This
	// is the one compression pointer we emit, and every resolver understands it.
	out = append(out, 0xC0, byte(headerLen))
	out = binary.BigEndian.AppendUint16(out, TypeA)
	out = binary.BigEndian.AppendUint16(out, ClassINET)
	out = binary.BigEndian.AppendUint32(out, ttl)
	out = binary.BigEndian.AppendUint16(out, 4)
	out = append(out, v4...)
	return out, nil
}

// AnswerEmpty builds a NOERROR response with no answers.
//
// This is what non-A queries get -- AAAA above all. Returning NOERROR with an
// empty answer section tells the client the name exists but has no record of
// that type, so it falls back to A and reaches the mediator. NXDOMAIN would
// instead convince it the name does not exist at all, and it would give up
// without ever connecting.
func (q *Query) AnswerEmpty() []byte {
	out := q.header(RcodeSuccess, 0)
	return append(out, q.question...)
}

// AnswerRefused builds a REFUSED response.
//
// Not used on the normal path, for the reason AnswerA explains. Kept for the
// case where a query is malformed enough that answering it properly is not
// possible.
func (q *Query) AnswerRefused() []byte {
	out := q.header(RcodeRefused, 0)
	return append(out, q.question...)
}

// header builds a 12-byte response header echoing the query's id.
func (q *Query) header(rcode uint16, ancount uint16) []byte {
	flags := uint16(flagResponse | flagRecursionAvailable)
	// Echo RD so a client that asked for recursion sees its own flag reflected,
	// which is what it expects from a resolver.
	flags |= q.Flags & flagRecursionDesired
	flags |= rcode & 0x000F

	out := make([]byte, 0, headerLen+len(q.question)+16)
	out = binary.BigEndian.AppendUint16(out, q.ID)
	out = binary.BigEndian.AppendUint16(out, flags)
	out = binary.BigEndian.AppendUint16(out, 1) // QDCOUNT, echoed
	out = binary.BigEndian.AppendUint16(out, ancount)
	out = binary.BigEndian.AppendUint16(out, 0) // NSCOUNT
	out = binary.BigEndian.AppendUint16(out, 0) // ARCOUNT
	return out
}

// TypeName renders a query type for logs.
func TypeName(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	case TypeCNAME:
		return "CNAME"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}
