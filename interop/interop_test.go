// Package interop exercises this library against Cloudflare Research's live
// Web Bot Auth deployment (the reference implementation in production):
//
//   - our Signer's output is judged by THEIR verifier (/v0/api/verify),
//   - our Verifier resolves keys from THEIR live key directory.
//
// Together with the vendored reference vectors (their signer → our
// verifier), this closes the interop loop in both directions.
//
// These tests hit the network; they are skipped unless WEBBOTAUTH_INTEROP=1.
package interop_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	webbotauth "github.com/WebDecoy/web-bot-auth"
	"github.com/WebDecoy/web-bot-auth/httpsig"
)

const (
	liveOrigin = "https://http-message-signatures-example.research.cloudflare.com"
	liveHost   = "http-message-signatures-example.research.cloudflare.com"
	verifyAPI  = liveOrigin + "/v0/api/verify"

	// The shared RFC 9421 Ed25519 test key: the live deployment trusts it,
	// and it is the same key as the reference vectors'.
	testKeyD = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU"
	testKeyX = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
)

func requireInterop(t *testing.T) {
	t.Helper()
	if os.Getenv("WEBBOTAUTH_INTEROP") != "1" {
		t.Skip("set WEBBOTAUTH_INTEROP=1 to run live interop tests")
	}
}

func testPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(testKeyD)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	wantPub, err := base64.RawURLEncoding.DecodeString(testKeyX)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.PublicKey(wantPub).Equal(priv.Public()) {
		t.Fatal("test key seed does not produce the expected public key")
	}
	return priv
}

func fetchBody(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, strings.TrimSpace(string(body))
}

// Our signer → their production verifier.
func TestLiveVerifierAcceptsOurSignature(t *testing.T) {
	requireInterop(t)
	signer, err := webbotauth.NewSigner(testPrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, verifyAPI, nil)
	if err := signer.SignRequest(req); err != nil {
		t.Fatal(err)
	}
	status, body := fetchBody(t, req)
	if status != http.StatusOK || body != "valid" {
		t.Fatalf("live verifier: HTTP %d, body %q (want \"valid\")\nSignature-Input: %s",
			status, body, req.Header.Get("Signature-Input"))
	}
}

func TestLiveVerifierNeutralWithoutSignature(t *testing.T) {
	requireInterop(t)
	req, _ := http.NewRequest(http.MethodGet, verifyAPI, nil)
	if _, body := fetchBody(t, req); body != "neutral" {
		t.Fatalf("unsigned request: body %q, want \"neutral\"", body)
	}
}

func TestLiveVerifierRejectsTamperedSignature(t *testing.T) {
	requireInterop(t)
	signer, err := webbotauth.NewSigner(testPrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, verifyAPI, nil)
	if err := signer.SignRequest(req); err != nil {
		t.Fatal(err)
	}
	// Corrupt one byte of the base64 signature payload.
	sig := req.Header.Get("Signature")
	mid := len(sig) / 2
	c := byte('A')
	if sig[mid] == 'A' {
		c = 'B'
	}
	req.Header.Set("Signature", sig[:mid]+string(c)+sig[mid+1:])
	if _, body := fetchBody(t, req); !strings.HasPrefix(body, "invalid") {
		t.Fatalf("tampered request: body %q, want invalid*", body)
	}
}

// Their live directory → our parser: the published test key must parse and
// its kid must equal the thumbprint we compute.
func TestLiveDirectoryParsesAndThumbprintMatches(t *testing.T) {
	requireInterop(t)
	req, _ := http.NewRequest(http.MethodGet, liveOrigin+webbotauth.WellKnownDirectoryPath, nil)
	status, body := fetchBody(t, req)
	if status != http.StatusOK {
		t.Fatalf("directory fetch: HTTP %d", status)
	}
	set, err := webbotauth.ParseKeySet([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range set.Keys {
		tp, err := k.Thumbprint()
		if err != nil {
			continue
		}
		if tp == k.Kid && k.X == testKeyX {
			found = true
		}
	}
	if !found {
		t.Fatalf("test key with matching kid/thumbprint not found in live directory: %s", body)
	}
}

// Full loop with live key discovery: our signer names their origin in
// Signature-Agent, and our verifier fetches THEIR live directory over the
// real network to resolve the key. Also exercises millisecond-nbf
// normalization, which their directory requires.
func TestOurVerifierResolvesFromLiveDirectory(t *testing.T) {
	requireInterop(t)
	signer, err := webbotauth.NewSigner(testPrivateKey(t), webbotauth.WithSignatureAgent(liveOrigin))
	if err != nil {
		t.Fatal(err)
	}
	outbound, _ := http.NewRequest(http.MethodGet, "https://example.com/protected", nil)
	if err := signer.SignRequest(outbound); err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse("https://example.com/protected")
	inbound := &httpsig.Request{
		Method:    http.MethodGet,
		Scheme:    u.Scheme,
		Authority: u.Host,
		Path:      u.EscapedPath(),
		Header:    outbound.Header,
	}
	verifier := webbotauth.NewVerifier(webbotauth.WithDirectoryAllowlist(liveHost))
	res := verifier.Verify(context.Background(), inbound)
	if res.Status != webbotauth.StatusVerified {
		t.Fatalf("status = %v, errors = %v", res.Status, res.Errors)
	}
	if res.Directory != liveOrigin+webbotauth.WellKnownDirectoryPath {
		t.Errorf("directory = %q", res.Directory)
	}
}
