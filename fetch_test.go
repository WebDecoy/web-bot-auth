package webbotauth_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	webbotauth "github.com/WebDecoy/web-bot-auth"
)

func TestFetchDirectory(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := webbotauth.NewSigner(priv)
	jwk := signer.PublicJWK()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != webbotauth.WellKnownDirectoryPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/http-message-signatures-directory+json")
		json.NewEncoder(w).Encode(webbotauth.KeySet{Keys: []webbotauth.JWK{jwk}})
	}))
	defer srv.Close()

	set, err := webbotauth.FetchDirectoryWithClient(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("got %d keys", len(set.Keys))
	}

	// The raw public key round-trips to the signer's key.
	raw, err := set.Keys[0].RawPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	if !ed25519.PublicKey(decoded).Equal(ed25519.PublicKey(want)) {
		t.Error("raw public key does not match JWK")
	}

	// Thumbprint is the keyid a signature would carry.
	if tp, err := set.Keys[0].Thumbprint(); err != nil || tp == "" {
		t.Errorf("thumbprint: %v %q", err, tp)
	}
}

func TestFetchDirectoryErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := webbotauth.FetchDirectoryWithClient(context.Background(), srv.Client(), srv.URL); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 error, got %v", err)
	}
}

func TestFetchDirectoryRejectsRedirectAndWrongMediaType(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer redirect.Close()
	if _, err := webbotauth.FetchDirectoryWithClient(context.Background(), redirect.Client(), redirect.URL); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect was followed or accepted: %v", err)
	}

	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `{"keys":[]}`)
	}))
	defer html.Close()
	if _, err := webbotauth.FetchDirectoryWithClient(context.Background(), html.Client(), html.URL); err == nil || !strings.Contains(err.Error(), "Content-Type") {
		t.Fatalf("wrong media type was accepted: %v", err)
	}
}

func TestRawPublicKeyRejectsRSA(t *testing.T) {
	k := webbotauth.JWK{Kty: "RSA", N: "abc", E: "AQAB"}
	if _, err := k.RawPublicKey(); err == nil {
		t.Error("expected error for RSA key")
	}
}
