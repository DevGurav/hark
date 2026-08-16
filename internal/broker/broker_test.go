package broker

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/DevGurav/hark/internal/policy"
)

const realKey = "AIzaSyREAL-SECRET-VALUE-do-not-log-me"

func testPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`
allow_hosts = ["generativelanguage.googleapis.com"]

[secrets]
gemini_api_key = "GEMINI_API_KEY"
`), "test.toml")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testBroker(t *testing.T) *Broker {
	t.Helper()
	b, err := New("01TESTRUN", map[string]string{"gemini_api_key": realKey}, testPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The property this package exists for. If this test ever fails, the bundle
// format has become a credential disclosure mechanism.
func TestRealSecretNeverLeavesTheBoundary(t *testing.T) {
	b := testBroker(t)

	if got := b.Placeholders()["GEMINI_API_KEY"]; strings.Contains(got, realKey) {
		t.Fatal("the agent's environment contains the real secret")
	}

	h := http.Header{"X-Goog-Api-Key": []string{b.Placeholders()["GEMINI_API_KEY"]}}
	body := []byte(`{"key":"` + b.Placeholders()["GEMINI_API_KEY"] + `"}`)

	_, _, injections, err := b.Inject("generativelanguage.googleapis.com", h, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(injections) != 1 {
		t.Fatalf("expected 1 injection, got %d", len(injections))
	}

	// The inputs the caller will record must be untouched.
	if strings.Contains(h.Get("X-Goog-Api-Key"), realKey) {
		t.Fatal("Inject mutated the caller's headers, so the recorded copy holds the real secret")
	}
	if strings.Contains(string(body), realKey) {
		t.Fatal("Inject mutated the caller's body, so the recorded copy holds the real secret")
	}

	// And nothing in the injection record carries the value.
	in := injections[0]
	if strings.Contains(in.Ref, realKey) || strings.Contains(in.Placeholder, realKey) {
		t.Fatal("an injection record carries the real secret")
	}
	if strings.Contains(string(in.ValueHash), realKey) {
		t.Fatal("the value hash carries the real secret")
	}
	if len(in.ValueHash) != 32 {
		t.Fatalf("expected a 32-byte hash, got %d", len(in.ValueHash))
	}
}

func TestInjectSubstitutesForAllowedHost(t *testing.T) {
	b := testBroker(t)
	ph := b.Placeholders()["GEMINI_API_KEY"]

	h := http.Header{"Authorization": []string{"Bearer " + ph}}
	body := []byte(`{"key":"` + ph + `"}`)

	outH, outB, injections, err := b.Inject("generativelanguage.googleapis.com", h, body)
	if err != nil {
		t.Fatal(err)
	}
	if outH.Get("Authorization") != "Bearer "+realKey {
		t.Fatalf("header not substituted: %q", outH.Get("Authorization"))
	}
	if !strings.Contains(string(outB), realKey) {
		t.Fatalf("body not substituted: %s", outB)
	}
	if len(injections) != 1 || injections[0].Ref != "gemini_api_key" {
		t.Fatalf("unexpected injections: %+v", injections)
	}
}

// The second line of defence. The mediator checks policy before calling Inject;
// if that check ever regresses, the credential still must not travel.
func TestNoInjectionForDisallowedHost(t *testing.T) {
	b := testBroker(t)
	ph := b.Placeholders()["GEMINI_API_KEY"]

	h := http.Header{"Authorization": []string{"Bearer " + ph}}
	body := []byte(ph)

	outH, outB, injections, err := b.Inject("evil.example", h, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(injections) != 0 {
		t.Fatal("substituted a credential for a host the policy denies")
	}
	if strings.Contains(outH.Get("Authorization"), realKey) || strings.Contains(string(outB), realKey) {
		t.Fatal("the real secret was sent to a denied host")
	}
	if !strings.Contains(outH.Get("Authorization"), ph) {
		t.Fatal("the placeholder should pass through untouched")
	}
}

func TestNoPlaceholderMeansNoInjection(t *testing.T) {
	b := testBroker(t)
	h := http.Header{"Content-Type": []string{"application/json"}}
	body := []byte(`{"contents":"nothing secret here"}`)

	_, outB, injections, err := b.Inject("generativelanguage.googleapis.com", h, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(injections) != 0 {
		t.Fatalf("injected without a placeholder present: %+v", injections)
	}
	if string(outB) != string(body) {
		t.Fatal("body changed when nothing needed substituting")
	}
}

func TestContainsSecretCatchesALeak(t *testing.T) {
	b := testBroker(t)

	if _, found := b.ContainsSecret([]byte("perfectly ordinary log line")); found {
		t.Fatal("false positive")
	}
	if _, found := b.ContainsSecret(nil); found {
		t.Fatal("false positive on empty input")
	}

	ref, found := b.ContainsSecret([]byte("...prefix " + realKey + " suffix..."))
	if !found {
		t.Fatal("failed to detect a real secret in bytes about to be written")
	}
	if ref != "gemini_api_key" {
		t.Fatalf("wrong ref reported: %q", ref)
	}
}

// A placeholder must name its run. One that escaped a previous run should be
// recognisably foreign rather than quietly substituted with this run's value.
func TestPlaceholdersAreRunScopedAndDistinct(t *testing.T) {
	a := Placeholder("RUN-A", "gemini_api_key")
	c := Placeholder("RUN-B", "gemini_api_key")
	if a == c {
		t.Fatal("placeholders from different runs collide")
	}
	if Placeholder("RUN-A", "one") == Placeholder("RUN-A", "two") {
		t.Fatal("placeholders for different secrets collide")
	}
	if !strings.Contains(a, "RUN-A") {
		t.Fatal("placeholder does not name its run")
	}
}

// If one secret's value contains another's, the longer must be replaced first.
// Otherwise the shorter substitution mangles the longer value, which then fails
// to match and travels unsubstituted.
func TestOverlappingSecretValues(t *testing.T) {
	p, err := policy.Parse([]byte(`
allow_hosts = ["api.example.com"]

[secrets]
short = "SHORT_KEY"
long  = "LONG_KEY"
`), "t.toml")
	if err != nil {
		t.Fatal(err)
	}

	b, err := New("01RUN", map[string]string{
		"short": "abc123",
		"long":  "abc123-extended-suffix",
	}, p)
	if err != nil {
		t.Fatal(err)
	}

	ph := b.Placeholders()
	body := []byte(ph["SHORT_KEY"] + "|" + ph["LONG_KEY"])

	_, outB, injections, err := b.Inject("api.example.com", ph2Header(), body)
	if err != nil {
		t.Fatal(err)
	}
	if len(injections) != 2 {
		t.Fatalf("expected both secrets injected, got %d", len(injections))
	}
	if string(outB) != "abc123|abc123-extended-suffix" {
		t.Fatalf("overlapping values substituted incorrectly: %s", outB)
	}
}

func ph2Header() http.Header { return http.Header{} }

func TestNewRejectsBadInput(t *testing.T) {
	p := testPolicy(t)

	if _, err := New("", map[string]string{"a": "b"}, p); err == nil {
		t.Fatal("accepted an empty run id")
	}
	if _, err := New("01RUN", map[string]string{"a": "b"}, nil); err == nil {
		t.Fatal("accepted a nil policy")
	}
	if _, err := New("01RUN", map[string]string{"gemini_api_key": ""}, p); err == nil {
		t.Fatal("accepted an empty secret value")
	}
}

// A missing credential must stop the run at startup, not halfway through when
// the first model call gets a 401.
func TestResolveFromEnv(t *testing.T) {
	t.Setenv("HARK_TEST_KEY", "value-from-env")

	got, err := ResolveFromEnv(map[string]string{"k": "HARK_TEST_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if got["k"] != "value-from-env" {
		t.Fatalf("unexpected value %q", got["k"])
	}

	if _, err := ResolveFromEnv(map[string]string{"k": "HARK_TEST_DEFINITELY_UNSET"}); err == nil {
		t.Fatal("accepted a missing environment variable")
	}

	os.Setenv("HARK_TEST_EMPTY", "")
	defer os.Unsetenv("HARK_TEST_EMPTY")
	if _, err := ResolveFromEnv(map[string]string{"k": "HARK_TEST_EMPTY"}); err == nil {
		t.Fatal("accepted an empty environment variable")
	}
}
