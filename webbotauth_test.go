package webbotauth_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	webbotauth "github.com/WebDecoy/web-bot-auth"
	"github.com/WebDecoy/web-bot-auth/httpsig"
)

type e2eVector struct {
	Key            webbotauth.JWK `json:"key"`
	TargetURL      string         `json:"target_url"`
	CreatedMS      int64          `json:"created_ms"`
	Label          string         `json:"label"`
	Signature      string         `json:"signature"`
	SignatureInput string         `json:"signature_input"`
	SignatureAgent string         `json:"signature_agent"`
}

func loadE2EVectors(t *testing.T, name string) []e2eVector {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var vs []e2eVector
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

func vectorHTTPRequest(t *testing.T, v *e2eVector) *httpsig.Request {
	t.Helper()
	u, err := url.Parse(v.TargetURL)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("Signature", v.Signature)
	h.Set("Signature-Input", v.SignatureInput)
	if v.SignatureAgent != "" {
		h.Set("Signature-Agent", v.SignatureAgent)
	}
	return &httpsig.Request{
		Method:    "GET",
		Scheme:    u.Scheme,
		Authority: u.Host,
		Path:      u.EscapedPath(),
		Header:    h,
	}
}

// Full verifier flow over the reference vectors with pinned (static) keys.
// The clock is pinned inside each vector's validity window; v1 vectors are
// expired in real time, which doubles as the expiry test below.
func TestVerifyReferenceVectorsStaticKeys(t *testing.T) {
	for _, file := range []string{"web_bot_auth_architecture_v1.json", "web_bot_auth_architecture_v2.json"} {
		t.Run(file, func(t *testing.T) {
			for _, v := range loadE2EVectors(t, file) {
				v := v
				t.Run(v.Label, func(t *testing.T) {
					// The v2 vectors use ~100-year expiries so they stay
					// verifiable without clock mocking; lift the (correct)
					// 24h default lifetime cap for them.
					verifier := webbotauth.NewVerifier(
						webbotauth.WithKeys(v.Key),
						webbotauth.WithClock(func() time.Time { return time.UnixMilli(v.CreatedMS).Add(time.Minute) }),
						webbotauth.WithMaxLifetime(200*365*24*time.Hour),
						webbotauth.WithLegacyMissingSignatureAgent(),
					)
					res := verifier.Verify(context.Background(), vectorHTTPRequest(t, &v))
					if res.Status != webbotauth.StatusVerified {
						t.Fatalf("status = %v, errors = %v", res.Status, res.Errors)
					}
					wantKeyID, _ := mustKeyID(t, v.Key)
					if res.KeyID != wantKeyID {
						t.Errorf("keyid = %q, want %q", res.KeyID, wantKeyID)
					}
					if res.Label != v.Label {
						t.Errorf("label = %q, want %q", res.Label, v.Label)
					}
				})
			}
		})
	}
}

func mustKeyID(t *testing.T, k webbotauth.JWK) (string, webbotauth.JWK) {
	t.Helper()
	tp, err := k.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return tp, k
}

func TestVerifyExpired(t *testing.T) {
	vs := loadE2EVectors(t, "web_bot_auth_architecture_v1.json")
	v := vs[0] // expires 2025-01-01, long past
	verifier := webbotauth.NewVerifier(webbotauth.WithKeys(v.Key), webbotauth.WithLegacyMissingSignatureAgent())
	res := verifier.Verify(context.Background(), vectorHTTPRequest(t, &v))
	if res.Status != webbotauth.StatusInvalid {
		t.Fatalf("status = %v, want invalid", res.Status)
	}
	if !containsError(res.Errors, "expired") {
		t.Errorf("expected an expiry error, got %v", res.Errors)
	}
}

func TestVerifyNoSignature(t *testing.T) {
	verifier := webbotauth.NewVerifier()
	req := &httpsig.Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", Header: http.Header{}}
	if res := verifier.Verify(context.Background(), req); res.Status != webbotauth.StatusNoSignature {
		t.Fatalf("status = %v, want no-signature", res.Status)
	}
	// A non-web-bot-auth RFC 9421 signature is also not our protocol.
	req.Header.Set("Signature-Input", `sig1=("@authority");created=1;expires=2;keyid="k";tag="other-protocol"`)
	req.Header.Set("Signature", `sig1=:aGVsbG8=:`)
	if res := verifier.Verify(context.Background(), req); res.Status != webbotauth.StatusNoSignature {
		t.Fatalf("status with foreign tag = %v, want no-signature", res.Status)
	}
}

func TestVerifyTamperedAndUnknownKey(t *testing.T) {
	vs := loadE2EVectors(t, "web_bot_auth_architecture_v2.json")
	v := vs[0]
	clock := webbotauth.WithClock(func() time.Time { return time.UnixMilli(v.CreatedMS).Add(time.Minute) })

	// Wrong authority → base mismatch → invalid.
	verifier := webbotauth.NewVerifier(webbotauth.WithKeys(v.Key), clock)
	req := vectorHTTPRequest(t, &v)
	req.Authority = "evil.example"
	if res := verifier.Verify(context.Background(), req); res.Status != webbotauth.StatusInvalid {
		t.Fatalf("tampered authority: status = %v, want invalid", res.Status)
	}

	// No key material available → invalid with unknown-key error.
	verifier = webbotauth.NewVerifier(clock)
	if res := verifier.Verify(context.Background(), vectorHTTPRequest(t, &v)); res.Status != webbotauth.StatusInvalid {
		t.Fatalf("unknown key: status = %v, want invalid", res.Status)
	}
}

// End-to-end: our Signer signs a live request; the Verifier resolves the key
// from a real (test TLS) directory named by Signature-Agent, subject to the
// allowlist.
func TestSignerVerifierDirectoryRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var dir *httptest.Server
	dir = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != webbotauth.WellKnownDirectoryPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/http-message-signatures-directory+json")
		signer, _ := webbotauth.NewSigner(priv)
		json.NewEncoder(w).Encode(webbotauth.KeySet{Keys: []webbotauth.JWK{signer.PublicJWK()}})
	}))
	defer dir.Close()

	dirHost := strings.TrimPrefix(dir.URL, "https://")

	signer, err := webbotauth.NewSigner(priv, webbotauth.WithSignatureAgent(dir.URL))
	if err != nil {
		t.Fatal(err)
	}
	outbound, _ := http.NewRequest("GET", "https://example.com/protected?x=1", nil)
	if err := signer.SignRequest(outbound); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"Signature", "Signature-Input", "Signature-Agent"} {
		if outbound.Header.Get(h) == "" {
			t.Fatalf("signer did not set %s", h)
		}
	}

	inbound := &httpsig.Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/protected",
		Query:     "?x=1",
		Header:    outbound.Header,
	}

	verifier := webbotauth.NewVerifier(
		webbotauth.WithDirectoryAllowlist(strings.Split(dirHost, ":")[0]),
		webbotauth.WithHTTPClient(dir.Client()),
	)
	res := verifier.Verify(context.Background(), inbound)
	if res.Status != webbotauth.StatusVerified {
		t.Fatalf("status = %v, errors = %v", res.Status, res.Errors)
	}
	if res.Agent != dir.URL {
		t.Errorf("agent = %q, want %q", res.Agent, dir.URL)
	}
	if res.Directory == "" || res.Algorithm != httpsig.AlgEd25519 {
		t.Errorf("unexpected result: %+v", res)
	}

	// Same request, allowlist without the directory host → invalid, and the
	// error names the policy.
	strict := webbotauth.NewVerifier(
		webbotauth.WithDirectoryAllowlist("agents.trusted.example"),
		webbotauth.WithHTTPClient(dir.Client()),
	)
	res = strict.Verify(context.Background(), inbound)
	if res.Status != webbotauth.StatusInvalid {
		t.Fatalf("allowlist bypass: status = %v", res.Status)
	}
	if !containsError(res.Errors, "allowlist") {
		t.Errorf("expected allowlist error, got %v", res.Errors)
	}

	// Tampering with the signed request after signing → invalid.
	inbound.Path = "/other"
	inbound.Query = ""
	res = verifier.Verify(context.Background(), inbound)
	if res.Status != webbotauth.StatusVerified {
		// @authority-only coverage means path tampering alone doesn't break
		// the signature — that is protocol behavior, not a bug. Flip the
		// authority to prove the signature binds.
		t.Fatalf("unexpected: %v %v", res.Status, res.Errors)
	}
	inbound.Authority = "evil.example"
	if res = verifier.Verify(context.Background(), inbound); res.Status != webbotauth.StatusInvalid {
		t.Fatalf("authority tamper: status = %v", res.Status)
	}
}

func TestSignatureAgentMustBeCovered(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := webbotauth.NewSigner(priv)

	outbound, _ := http.NewRequest("GET", "https://example.com/", nil)
	if err := signer.SignRequest(outbound); err != nil {
		t.Fatal(err)
	}
	// Inject a Signature-Agent header that the signature does not cover:
	// the draft says it MUST be covered, so verification must refuse.
	outbound.Header.Set("Signature-Agent", `sig1="https://mallory.example"`)

	verifier := webbotauth.NewVerifier(webbotauth.WithKeys(signer.PublicJWK()))
	inbound := &httpsig.Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", Header: outbound.Header}
	res := verifier.Verify(context.Background(), inbound)
	if res.Status != webbotauth.StatusInvalid {
		t.Fatalf("status = %v, want invalid", res.Status)
	}
	if !containsError(res.Errors, "not covered") {
		t.Errorf("expected coverage error, got %v", res.Errors)
	}
}

func TestSignerBindsDictionarySignatureAgentMember(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, err := webbotauth.NewSigner(priv, webbotauth.WithSignatureAgent("https://agent.example"))
	if err != nil {
		t.Fatal(err)
	}
	outbound, _ := http.NewRequest("GET", "https://example.com/", nil)
	if err := signer.SignRequest(outbound); err != nil {
		t.Fatal(err)
	}
	if got := outbound.Header.Get("Signature-Agent"); got != `sig1="https://agent.example"` {
		t.Fatalf("Signature-Agent = %q", got)
	}
	if got := outbound.Header.Get("Signature-Input"); !strings.Contains(got, `"signature-agent";key="sig1"`) {
		t.Fatalf("Signature-Input does not bind the sig1 dictionary member: %s", got)
	}

	inbound := &httpsig.Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", Header: outbound.Header}
	res := webbotauth.NewVerifier(webbotauth.WithKeys(signer.PublicJWK())).Verify(context.Background(), inbound)
	if res.Status != webbotauth.StatusVerified {
		t.Fatalf("status = %v, errors = %v", res.Status, res.Errors)
	}
}

func TestSignerLegacySignatureAgentInteropMode(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, err := webbotauth.NewSigner(priv,
		webbotauth.WithSignatureAgent("https://agent.example"),
		webbotauth.WithLegacySignatureAgent())
	if err != nil {
		t.Fatal(err)
	}
	outbound, _ := http.NewRequest("GET", "https://example.com/", nil)
	if err := signer.SignRequest(outbound); err != nil {
		t.Fatal(err)
	}
	if got := outbound.Header.Get("Signature-Agent"); got != `"https://agent.example"` {
		t.Fatalf("legacy Signature-Agent = %q", got)
	}
	if got := outbound.Header.Get("Signature-Input"); !strings.Contains(got, `"signature-agent"`) || strings.Contains(got, `"signature-agent";key=`) {
		t.Fatalf("legacy Signature-Input = %s", got)
	}

	inbound := &httpsig.Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", Header: outbound.Header}
	res := webbotauth.NewVerifier(webbotauth.WithKeys(signer.PublicJWK())).Verify(context.Background(), inbound)
	if res.Status != webbotauth.StatusVerified {
		t.Fatalf("status = %v, errors = %v", res.Status, res.Errors)
	}
}

func TestVerifierRejectsWholeDictionaryHeaderCoverage(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := webbotauth.NewSigner(priv,
		webbotauth.WithSignatureAgent("https://agent.example"),
		webbotauth.WithLegacySignatureAgent())
	outbound, _ := http.NewRequest("GET", "https://example.com/", nil)
	if err := signer.SignRequest(outbound); err != nil {
		t.Fatal(err)
	}
	outbound.Header.Set("Signature-Agent", `sig1="https://agent.example"`)

	inbound := &httpsig.Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", Header: outbound.Header}
	res := webbotauth.NewVerifier(webbotauth.WithKeys(signer.PublicJWK())).Verify(context.Background(), inbound)
	if res.Status != webbotauth.StatusInvalid || !containsError(res.Errors, "dictionary member") {
		t.Fatalf("status = %v, errors = %v", res.Status, res.Errors)
	}
}

func TestNonceChecker(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := webbotauth.NewSigner(priv, webbotauth.WithSignatureAgent("https://agent.example"))
	outbound, _ := http.NewRequest("GET", "https://example.com/", nil)
	if err := signer.SignRequest(outbound); err != nil {
		t.Fatal(err)
	}
	inbound := &httpsig.Request{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", Header: outbound.Header}

	seen := map[string]bool{}
	verifier := webbotauth.NewVerifier(
		webbotauth.WithKeys(signer.PublicJWK()),
		webbotauth.WithNonceChecker(func(_ context.Context, nonce string, _ *webbotauth.Result) error {
			if seen[nonce] {
				return errors.New("replayed")
			}
			seen[nonce] = true
			return nil
		}),
	)
	if res := verifier.Verify(context.Background(), inbound); res.Status != webbotauth.StatusVerified {
		t.Fatalf("first use: %v %v", res.Status, res.Errors)
	}
	if res := verifier.Verify(context.Background(), inbound); res.Status != webbotauth.StatusInvalid {
		t.Fatalf("replay: status = %v, want invalid", res.Status)
	}
}

func TestRequestFromHTTP(t *testing.T) {
	r := httptest.NewRequest("GET", "https://example.com/a?b=1", nil)
	req := webbotauth.RequestFromHTTP(r, webbotauth.WithScheme("https"))
	if req.Authority != "example.com" || req.Path != "/a" || req.Query != "?b=1" || req.Scheme != "https" {
		t.Errorf("unexpected request: %+v", req)
	}
}

func containsError(errs []error, substr string) bool {
	for _, e := range errs {
		if e != nil && strings.Contains(e.Error(), substr) {
			return true
		}
	}
	return false
}

// TestDirectoryServedAsHTMLIsRejected wires the draft-02 §5.5.1 content-type
// gate end to end.
//
// The unit test on checkDirectoryContentType proves the function decides
// correctly; it does not prove the fetch path calls it. A gate that exists and
// is never invoked is the failure mode this repo has hit before, so the check
// that matters is this one: a server returning perfectly valid JWKS bytes under
// text/html must not verify.
//
// Before the gate, those bytes parsed, the key resolved, and the request
// verified — so an SSO interstitial or captive portal that happened to serve
// JSON could stand in for an operator's directory.
func TestDirectoryServedAsHTMLIsRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	dir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != webbotauth.WellKnownDirectoryPath {
			http.NotFound(w, r)
			return
		}
		// Valid key material, wrong media type. The bytes alone would parse.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		signer, _ := webbotauth.NewSigner(priv)
		json.NewEncoder(w).Encode(webbotauth.KeySet{Keys: []webbotauth.JWK{signer.PublicJWK()}})
	}))
	defer dir.Close()

	dirHost := strings.Split(strings.TrimPrefix(dir.URL, "https://"), ":")[0]

	signer, err := webbotauth.NewSigner(priv, webbotauth.WithSignatureAgent(dir.URL))
	if err != nil {
		t.Fatal(err)
	}
	outbound, _ := http.NewRequest("GET", "https://example.com/protected", nil)
	if err := signer.SignRequest(outbound); err != nil {
		t.Fatal(err)
	}

	verifier := webbotauth.NewVerifier(
		webbotauth.WithDirectoryAllowlist(dirHost),
		webbotauth.WithHTTPClient(dir.Client()),
	)
	res := verifier.Verify(context.Background(), &httpsig.Request{
		Method: "GET", Scheme: "https", Authority: "example.com",
		Path: "/protected", Header: outbound.Header,
	})

	if res.Status == webbotauth.StatusVerified {
		t.Fatal("a directory served as text/html verified; the content-type gate is not wired into the fetch path")
	}
}
