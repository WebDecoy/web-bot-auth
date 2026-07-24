package webbotauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

// FetchDirectory retrieves and parses the HTTP Message Signatures directory
// published at origin's well-known path. It is a convenience for the common
// case of loading a *known, trusted* agent's key set out of band (for
// example, a server curating an allowlist of signed agents) — distinct from
// the Verifier's request-driven, SSRF-guarded resolution of directories
// named by untrusted traffic.
//
// origin is a scheme://host base (e.g. "https://operator.openai.com"); the
// well-known path is appended. Non-2xx responses and bodies over 1 MiB are
// errors.
func FetchDirectory(ctx context.Context, origin string) (*KeySet, error) {
	return FetchDirectoryWithClient(ctx, http.DefaultClient, origin)
}

// FetchDirectoryWithClient is FetchDirectory with a caller-supplied client
// (timeouts, transport, proxying).
func FetchDirectoryWithClient(ctx context.Context, hc *http.Client, origin string) (*KeySet, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	url := origin + WellKnownDirectoryPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json, application/jwk-set+json, application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webbotauth: fetching directory %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("webbotauth: directory %q returned HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectoryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("webbotauth: reading directory %q: %w", url, err)
	}
	if int64(len(body)) > maxDirectoryBytes {
		return nil, fmt.Errorf("webbotauth: directory %q exceeds %d bytes", url, maxDirectoryBytes)
	}
	return ParseKeySet(body)
}

// RawPublicKey returns the base64 (standard encoding) raw public key bytes
// for an OKP/Ed25519 JWK — the form WebCrypto's importKey("raw", ...) and
// other non-JWK consumers expect. Only Ed25519 is supported.
func (k *JWK) RawPublicKey() (string, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" {
		return "", fmt.Errorf("webbotauth: RawPublicKey supports only Ed25519 OKP keys, got kty=%q crv=%q", k.Kty, k.Crv)
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return "", fmt.Errorf("webbotauth: invalid Ed25519 x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return "", fmt.Errorf("webbotauth: invalid Ed25519 key length %d", len(raw))
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
