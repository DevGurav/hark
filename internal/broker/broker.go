// Package broker keeps real credentials out of the agent's address space.
//
// The agent's environment holds a placeholder. The real value is substituted at
// the boundary, on the way out, and only for hosts the policy allows. So a
// prompt-injected agent that reads its own environment and posts it somewhere
// exfiltrates a placeholder, and the attempt is recorded — which is why the
// demo shows two independent controls rather than one.
//
// The invariant this package exists to hold: a real secret value must never
// reach the event log. Bundles are meant to be handed to reviewers and anchored
// in a public transparency log. A format that leaked the credential it protected
// would be worse than no format at all.
package broker

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/policy"
)

// Injection records that a substitution happened. It is what the mediator turns
// into a SecretInjected event, and it deliberately carries no value — only a
// reference, the placeholder the agent held, and a hash.
type Injection struct {
	Ref         string
	Placeholder string
	ValueHash   []byte
}

// Broker performs the substitution.
type Broker struct {
	runID string
	pol   *policy.Policy

	// byRef maps a logical secret name to its placeholder and real value.
	byRef map[string]secret
	// order is byRef's keys, sorted, so substitution is deterministic when one
	// value happens to contain another.
	order []string
}

type secret struct {
	placeholder string
	value       string
}

// ResolveFromEnv reads the real values out of the supervisor's own environment,
// given the policy's logical-name to variable-name mapping.
//
// Separated from New so the substitution logic stays testable without touching
// process environment, and so a missing credential fails at startup rather than
// halfway through a run.
func ResolveFromEnv(secrets map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(secrets))
	var missing []string
	for logical, envName := range secrets {
		v, ok := os.LookupEnv(envName)
		if !ok || v == "" {
			missing = append(missing, fmt.Sprintf("%s (%s)", logical, envName))
			continue
		}
		out[logical] = v
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("broker: no value in the environment for: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// New builds a broker. values maps a logical secret name to its real value.
//
// The policy is held so Inject can refuse to substitute for a host the policy
// does not allow. The mediator checks policy too; this is the second check. If a
// bug ever lets a denied request through the first one, the credential still
// does not travel with it.
func New(runID string, values map[string]string, pol *policy.Policy) (*Broker, error) {
	if runID == "" {
		return nil, errors.New("broker: empty run id")
	}
	if pol == nil {
		return nil, errors.New("broker: nil policy")
	}

	b := &Broker{
		runID: runID,
		pol:   pol,
		byRef: make(map[string]secret, len(values)),
	}
	for logical, v := range values {
		if v == "" {
			return nil, fmt.Errorf("broker: secret %q has an empty value", logical)
		}
		b.byRef[logical] = secret{
			placeholder: Placeholder(runID, logical),
			value:       v,
		}
		b.order = append(b.order, logical)
	}

	// Longest value first. If one secret's value is a substring of another's,
	// replacing the shorter one first would leave a mangled remnant of the
	// longer, which would then fail to match and silently travel unsubstituted.
	sort.Slice(b.order, func(i, j int) bool {
		vi, vj := b.byRef[b.order[i]].value, b.byRef[b.order[j]].value
		if len(vi) != len(vj) {
			return len(vi) > len(vj)
		}
		return b.order[i] < b.order[j]
	})
	return b, nil
}

// Placeholder is the token the agent sees in place of a credential.
//
// It includes the run id so a placeholder leaked from one run is recognisable
// and useless in another, and the logical name so two secrets never collide —
// without that, a substitution could not tell which credential to insert.
func Placeholder(runID, logical string) string {
	return "hark-placeholder-" + runID + "-" + logical
}

// Placeholders returns the environment additions for the agent: the variable
// name from the policy mapped to the placeholder value.
func (b *Broker) Placeholders() map[string]string {
	out := make(map[string]string, len(b.byRef))
	for logical, envName := range b.pol.Secrets {
		if s, ok := b.byRef[logical]; ok {
			out[envName] = s.placeholder
		}
	}
	return out
}

// Inject substitutes real values into an outbound request.
//
// Inputs are never mutated. The caller records the originals — which still hold
// placeholders — and sends the returned copies. Making that structural rather
// than a rule to remember is what stops a real credential reaching the log.
//
// A host the policy does not allow gets no substitution at all.
func (b *Broker) Inject(host string, h http.Header, body []byte) (http.Header, []byte, []Injection, error) {
	if _, allowed := b.pol.AllowsHost(host); !allowed {
		return cloneHeader(h), cloneBody(body), nil, nil
	}

	outH := cloneHeader(h)
	outB := cloneBody(body)
	var injections []Injection

	for _, logical := range b.order {
		s := b.byRef[logical]
		hit := false

		for key, vals := range outH {
			for i, v := range vals {
				if strings.Contains(v, s.placeholder) {
					outH[key][i] = strings.ReplaceAll(v, s.placeholder, s.value)
					hit = true
				}
			}
		}

		if len(outB) > 0 && strings.Contains(string(outB), s.placeholder) {
			outB = []byte(strings.ReplaceAll(string(outB), s.placeholder, s.value))
			hit = true
		}

		if hit {
			vh := hashchain.Leaf(0, 0, []byte(s.value))
			injections = append(injections, Injection{
				Ref:         logical,
				Placeholder: s.placeholder,
				ValueHash:   vh[:],
			})
		}
	}
	return outH, outB, injections, nil
}

// ContainsSecret reports whether b holds any real credential value.
//
// This is the assertion the recorder runs on anything about to be written to the
// log. Substitution already happens only on copies, so this should never fire —
// which is exactly why it is worth checking. A silent leak into an artifact
// designed to be published is not a failure anyone would notice in time.
func (b *Broker) ContainsSecret(data []byte) (ref string, found bool) {
	if len(data) == 0 {
		return "", false
	}
	s := string(data)
	for _, logical := range b.order {
		if strings.Contains(s, b.byRef[logical].value) {
			return logical, true
		}
	}
	return "", false
}

// Refs returns the logical secret names, sorted, for diagnostics.
func (b *Broker) Refs() []string {
	out := append([]string(nil), b.order...)
	sort.Strings(out)
	return out
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vals := range h {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}

func cloneBody(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
