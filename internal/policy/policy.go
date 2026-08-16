// Package policy loads the run policy: the allowlist that decides what an agent
// may reach and touch.
//
// This is an allowlist, not a policy language. Every rule is an exact match, and
// anything the file does not explicitly permit is denied. A richer language is a
// v1.0 concern -- a half-implemented matcher is a security bug that looks like a
// feature, and the failure mode is silent over-permission.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/DevGurav/hark/internal/hashchain"
)

// Policy is the parsed, validated run policy.
type Policy struct {
	// AllowHosts are exact hostnames the agent may reach. No wildcards.
	AllowHosts []string `toml:"allow_hosts"`

	// ReadPaths and WritePaths scope the agent's filesystem view. Absolute paths
	// only, and the bundle must never be reachable through either.
	ReadPaths  []string `toml:"read_paths"`
	WritePaths []string `toml:"write_paths"`

	// Secrets maps a logical name to the environment variable the agent sees
	// holding its placeholder. The real value is injected at the boundary and
	// never enters the agent's address space.
	Secrets map[string]string `toml:"secrets"`
}

// Load reads and validates a policy file.
//
// It returns the raw bytes alongside the parsed policy so the recorded
// PolicyHash covers exactly what was on disk, rather than a re-serialisation of
// the parsed form. Those differ whenever the file has comments, ordering or
// formatting the parser discards -- and the thing a reviewer will diff against
// is the file, not our idea of it.
func Load(path string) (*Policy, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	p, err := Parse(raw, path)
	if err != nil {
		return nil, nil, err
	}
	return p, raw, nil
}

// Parse validates policy bytes. name is used only in error messages.
func Parse(raw []byte, name string) (*Policy, error) {
	var p Policy
	md, err := toml.Decode(string(raw), &p)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	// An unrecognised key is an error, never a warning. A typo in `allow_hosts`
	// would otherwise produce an empty allowlist that denies everything, or --
	// far worse in a future with more keys -- silently skip a restriction the
	// author believed they had written.
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("%s: unknown key(s): %s", name, strings.Join(keys, ", "))
	}

	if err := p.validate(name); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) validate(name string) error {
	seen := make(map[string]bool, len(p.AllowHosts))
	for i, h := range p.AllowHosts {
		if err := validHost(h); err != nil {
			return fmt.Errorf("%s: allow_hosts[%d] %q: %w", name, i, h, err)
		}
		lower := strings.ToLower(h)
		if seen[lower] {
			return fmt.Errorf("%s: allow_hosts contains %q twice", name, h)
		}
		seen[lower] = true
		p.AllowHosts[i] = lower
	}

	// path.Clean, never filepath.Clean. These are paths inside a Linux namespace,
	// so they are slash-separated regardless of the operating system doing the
	// parsing -- filepath.Clean would rewrite "/app" to "\app" on a Windows host
	// and hand the launcher a path that cannot exist.
	for i, p2 := range p.ReadPaths {
		if err := validPath(p2); err != nil {
			return fmt.Errorf("%s: read_paths[%d] %q: %w", name, i, p2, err)
		}
		p.ReadPaths[i] = path.Clean(p2)
	}
	for i, p2 := range p.WritePaths {
		if err := validPath(p2); err != nil {
			return fmt.Errorf("%s: write_paths[%d] %q: %w", name, i, p2, err)
		}
		p.WritePaths[i] = path.Clean(p2)
	}

	for logical, env := range p.Secrets {
		if logical == "" {
			return fmt.Errorf("%s: secrets has an empty logical name", name)
		}
		if err := validEnvName(env); err != nil {
			return fmt.Errorf("%s: secrets[%q] = %q: %w", name, logical, env, err)
		}
	}
	return nil
}

// validHost rejects anything that is not a bare hostname.
//
// The mediator compares against the TLS SNI and the DNS question, both of which
// carry a bare name. Accepting a URL, a port or a path here would produce a rule
// that can never match, and a rule that never matches reads as a restriction
// while behaving as an omission.
func validHost(h string) error {
	switch {
	case h == "":
		return errors.New("empty")
	case strings.ContainsAny(h, "*?"):
		// Wildcards are the specific thing this rejects loudly. "*.googleapis.com"
		// looks obviously correct and would silently permit
		// "evil.googleapis.com.attacker.example" under a naive suffix match.
		return errors.New("wildcards are not supported; list each host exactly")
	case strings.Contains(h, "://"):
		return errors.New("expected a bare hostname, not a URL")
	case strings.Contains(h, "/"):
		return errors.New("expected a bare hostname, not a path")
	case strings.Contains(h, ":"):
		return errors.New("expected a bare hostname, not host:port")
	case strings.ContainsAny(h, " \t"):
		return errors.New("contains whitespace")
	case strings.HasPrefix(h, ".") || strings.HasSuffix(h, "."):
		return errors.New("leading or trailing dot")
	case strings.Contains(h, ".."):
		return errors.New("empty label")
	case len(h) > 253:
		return errors.New("longer than 253 characters")
	}
	for _, r := range h {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			continue
		}
		return fmt.Errorf("invalid character %q", r)
	}
	return nil
}

func validPath(p string) error {
	switch {
	case p == "":
		return errors.New("empty")
	case !strings.HasPrefix(p, "/"):
		// Relative paths would resolve against whatever working directory the
		// supervisor happened to have, which is not a property anyone should be
		// reasoning about when deciding what an untrusted process can read.
		return errors.New("must be absolute")
	case strings.Contains(p, ".."):
		return errors.New("must not contain ..")
	}
	return nil
}

func validEnvName(n string) error {
	if n == "" {
		return errors.New("empty")
	}
	for i, r := range n {
		if r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return fmt.Errorf("invalid character %q for an environment variable name", r)
	}
	return nil
}

// AllowsHost reports whether the policy permits this host, and which rule said
// so. The rule string is recorded in the EgressDecision event: "denied" is not
// useful on its own, "denied, no rule matched" and "allowed by allow_hosts" are.
//
// Matching is exact and case-insensitive, because DNS names are.
func (p *Policy) AllowsHost(host string) (rule string, ok bool) {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, allowed := range p.AllowHosts {
		if allowed == h {
			return "allow_hosts:" + allowed, true
		}
	}
	return "", false
}

// Hash returns the BLAKE3 digest of the raw policy bytes, for the bundle header.
func Hash(raw []byte) hashchain.Hash {
	// Domain-separated as a leaf so a policy digest can never be confused with an
	// event leaf or an interior node elsewhere in the format.
	return hashchain.Leaf(0, 0, raw)
}
