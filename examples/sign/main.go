// Command sign generates an Ed25519 identity, prints the JWK Set to publish
// at /.well-known/http-message-signatures-directory, signs a request, and
// verifies it locally against the static key.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	webbotauth "github.com/WebDecoy/web-bot-auth"
	"github.com/WebDecoy/web-bot-auth/httpsig"
)

func main() {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := webbotauth.NewSigner(priv,
		webbotauth.WithSignatureAgent("https://mybot.example"),
	)
	if err != nil {
		log.Fatal(err)
	}

	directory, _ := json.MarshalIndent(webbotauth.KeySet{Keys: []webbotauth.JWK{signer.PublicJWK()}}, "", "  ")
	fmt.Printf("publish at https://mybot.example%s:\n%s\n\n", webbotauth.WellKnownDirectoryPath, directory)

	req, _ := http.NewRequest("GET", "https://example.com/page?q=1", nil)
	if err := signer.SignRequest(req); err != nil {
		log.Fatal(err)
	}
	for _, h := range []string{"Signature-Agent", "Signature-Input", "Signature"} {
		fmt.Printf("%s: %s\n", h, req.Header.Get(h))
	}

	// Re-verify what we just signed, as the receiving server would see it.
	inbound := &httpsig.Request{
		Method:    req.Method,
		Scheme:    req.URL.Scheme,
		Authority: req.URL.Host,
		Path:      req.URL.EscapedPath(),
		Query:     "?" + req.URL.RawQuery,
		Header:    req.Header,
	}
	verifier := webbotauth.NewVerifier(webbotauth.WithKeys(signer.PublicJWK()))
	res := verifier.Verify(context.Background(), inbound)
	fmt.Printf("\nlocal verification: %s (keyid %s)\n", res.Status, res.KeyID)
}
