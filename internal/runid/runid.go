// Package runid generates run identifiers.
//
// Run IDs are ULIDs: a 48-bit millisecond timestamp followed by 80 bits of
// randomness, rendered in Crockford base32 as 26 characters. The property that
// matters here is that they sort lexicographically in creation order, so a
// directory of bundles lists chronologically without needing to open any of
// them. UUIDv4 would have been one import away but sorts arbitrarily.
//
// Crockford base32 also excludes I, L, O and U, which keeps IDs readable aloud
// and unambiguous when someone copies one out of a terminal into an issue.
package runid

import (
	"crypto/rand"
	"errors"
	"time"
)

const encoding = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Length is the character count of every run ID.
const Length = 26

// New returns a fresh run ID for the current time.
func New() (string, error) { return at(time.Now()) }

func at(t time.Time) (string, error) {
	var id [16]byte

	ms := uint64(t.UnixMilli())
	id[0] = byte(ms >> 40)
	id[1] = byte(ms >> 32)
	id[2] = byte(ms >> 24)
	id[3] = byte(ms >> 16)
	id[4] = byte(ms >> 8)
	id[5] = byte(ms)

	if _, err := rand.Read(id[6:]); err != nil {
		return "", err
	}
	return encode(id), nil
}

// encode renders 16 bytes as 26 Crockford base32 characters.
//
// 26 characters carry 130 bits, so the leading character holds only the top 2
// bits of the value and the remaining 3 bits are always zero. That is the
// standard ULID layout, not an off-by-one.
func encode(id [16]byte) string {
	out := make([]byte, Length)
	out[0] = encoding[(id[0]&224)>>5]
	out[1] = encoding[id[0]&31]
	out[2] = encoding[(id[1]&248)>>3]
	out[3] = encoding[((id[1]&7)<<2)|((id[2]&192)>>6)]
	out[4] = encoding[(id[2]&62)>>1]
	out[5] = encoding[((id[2]&1)<<4)|((id[3]&240)>>4)]
	out[6] = encoding[((id[3]&15)<<1)|((id[4]&128)>>7)]
	out[7] = encoding[(id[4]&124)>>2]
	out[8] = encoding[((id[4]&3)<<3)|((id[5]&224)>>5)]
	out[9] = encoding[id[5]&31]
	out[10] = encoding[(id[6]&248)>>3]
	out[11] = encoding[((id[6]&7)<<2)|((id[7]&192)>>6)]
	out[12] = encoding[(id[7]&62)>>1]
	out[13] = encoding[((id[7]&1)<<4)|((id[8]&240)>>4)]
	out[14] = encoding[((id[8]&15)<<1)|((id[9]&128)>>7)]
	out[15] = encoding[(id[9]&124)>>2]
	out[16] = encoding[((id[9]&3)<<3)|((id[10]&224)>>5)]
	out[17] = encoding[id[10]&31]
	out[18] = encoding[(id[11]&248)>>3]
	out[19] = encoding[((id[11]&7)<<2)|((id[12]&192)>>6)]
	out[20] = encoding[(id[12]&62)>>1]
	out[21] = encoding[((id[12]&1)<<4)|((id[13]&240)>>4)]
	out[22] = encoding[((id[13]&15)<<1)|((id[14]&128)>>7)]
	out[23] = encoding[(id[14]&124)>>2]
	out[24] = encoding[((id[14]&3)<<3)|((id[15]&224)>>5)]
	out[25] = encoding[id[15]&31]
	return string(out)
}

// Valid reports whether s looks like a run ID this package produced.
func Valid(s string) error {
	if len(s) != Length {
		return errors.New("runid: wrong length")
	}
	for i := 0; i < len(s); i++ {
		found := false
		for j := 0; j < len(encoding); j++ {
			if s[i] == encoding[j] {
				found = true
				break
			}
		}
		if !found {
			return errors.New("runid: character outside the Crockford alphabet")
		}
	}
	return nil
}
