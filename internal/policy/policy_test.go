package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `
allow_hosts = ["generativelanguage.googleapis.com", "api.github.com"]
read_paths  = ["/app"]
write_paths = ["/tmp/work"]

[secrets]
gemini_api_key = "GEMINI_API_KEY"
`

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src), "test.toml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestParseValid(t *testing.T) {
	p := mustParse(t, valid)

	if len(p.AllowHosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(p.AllowHosts))
	}
	if p.ReadPaths[0] != "/app" || p.WritePaths[0] != "/tmp/work" {
		t.Fatalf("paths did not survive parsing: %+v", p)
	}
	if p.Secrets["gemini_api_key"] != "GEMINI_API_KEY" {
		t.Fatalf("secrets did not survive parsing: %+v", p.Secrets)
	}
}

// An empty policy is legitimate and denies everything. The deny-all test fixture
// depends on it, and a policy language that cannot express "nothing" would be a
// strange one.
func TestEmptyPolicyDeniesEverything(t *testing.T) {
	p := mustParse(t, "")
	if _, ok := p.AllowsHost("example.com"); ok {
		t.Fatal("an empty policy allowed a host")
	}
}

func TestAllowsHost(t *testing.T) {
	p := mustParse(t, valid)

	for _, h := range []string{
		"api.github.com",
		"API.GITHUB.COM",  // DNS is case-insensitive
		"api.github.com.", // fully-qualified form with the root dot
	} {
		rule, ok := p.AllowsHost(h)
		if !ok {
			t.Fatalf("%q should have been allowed", h)
		}
		if !strings.HasPrefix(rule, "allow_hosts:") {
			t.Fatalf("%q: unhelpful rule string %q", h, rule)
		}
	}

	// Near-misses that a suffix or substring match would wrongly permit. This is
	// the case wildcards exist to create, and why they are rejected.
	for _, h := range []string{
		"evil.example",
		"api.github.com.attacker.example",
		"notapi.github.com",
		"github.com",
		"",
	} {
		if _, ok := p.AllowsHost(h); ok {
			t.Fatalf("%q should NOT have been allowed", h)
		}
	}
}

func TestWildcardsRejected(t *testing.T) {
	for _, src := range []string{
		`allow_hosts = ["*.googleapis.com"]`,
		`allow_hosts = ["api.?ithub.com"]`,
	} {
		_, err := Parse([]byte(src), "t.toml")
		if err == nil {
			t.Fatalf("wildcard accepted: %s", src)
		}
		if !strings.Contains(err.Error(), "wildcard") {
			t.Fatalf("error should name the problem, got: %v", err)
		}
	}
}

// A typo in a key name must fail loudly. Silently ignoring it would produce a
// policy that looks restrictive and is not.
func TestUnknownKeyRejected(t *testing.T) {
	_, err := Parse([]byte(`allow_host = ["example.com"]`), "t.toml")
	if err == nil {
		t.Fatal("a misspelled key was accepted")
	}
	if !strings.Contains(err.Error(), "allow_host") {
		t.Fatalf("error should name the offending key, got: %v", err)
	}
}

func TestMalformedHostsRejected(t *testing.T) {
	cases := map[string]string{
		"url":         `allow_hosts = ["https://example.com"]`,
		"path":        `allow_hosts = ["example.com/v1"]`,
		"host:port":   `allow_hosts = ["example.com:443"]`,
		"empty":       `allow_hosts = [""]`,
		"trailing .":  `allow_hosts = ["example.com."]`,
		"empty label": `allow_hosts = ["a..b.com"]`,
		"whitespace":  `allow_hosts = ["exa mple.com"]`,
		"bad char":    `allow_hosts = ["exa_mple.com"]`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src), "t.toml"); err == nil {
				t.Fatalf("accepted a malformed host: %s", src)
			}
		})
	}
}

func TestDuplicateHostRejected(t *testing.T) {
	_, err := Parse([]byte(`allow_hosts = ["a.com", "A.COM"]`), "t.toml")
	if err == nil {
		t.Fatal("a duplicate host (differing only in case) was accepted")
	}
}

func TestRelativePathsRejected(t *testing.T) {
	for _, src := range []string{
		`read_paths = ["app"]`,
		`write_paths = ["./work"]`,
		`read_paths = ["/app/../etc"]`,
	} {
		if _, err := Parse([]byte(src), "t.toml"); err == nil {
			t.Fatalf("accepted a non-absolute or traversing path: %s", src)
		}
	}
}

func TestBadEnvNameRejected(t *testing.T) {
	src := `
[secrets]
key = "not-a-valid-env-name"
`
	if _, err := Parse([]byte(src), "t.toml"); err == nil {
		t.Fatal("accepted an invalid environment variable name")
	}
}

func TestLoadReturnsRawBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "demo.toml")
	// Comments and spacing the parser discards, but which the hash must cover.
	src := "# a comment\n" + valid + "\n\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	p, raw, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != src {
		t.Fatal("Load did not return the bytes exactly as they were on disk")
	}
	if len(p.AllowHosts) != 2 {
		t.Fatal("policy did not parse")
	}
}

// The recorded PolicyHash must be reproducible from the file, and must change
// when the file does -- including for changes the parser ignores, since a
// reviewer diffs the file rather than the parsed form.
func TestHashIsStableAndSensitive(t *testing.T) {
	a := []byte(valid)
	if Hash(a) != Hash([]byte(valid)) {
		t.Fatal("hashing the same bytes twice gave different results")
	}
	if Hash(a) == Hash([]byte("# comment\n"+valid)) {
		t.Fatal("a comment change did not change the hash")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, _, err := Load(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Fatal("expected an error for a missing policy file")
	}
}
