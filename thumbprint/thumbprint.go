// Package thumbprint computes JSON Web Key thumbprints as defined in
// RFC 7638, including the OKP variant from RFC 8037 Appendix A.3.
//
// Web Bot Auth uses the base64url-encoded JWK SHA-256 thumbprint of the
// signing key as the signature's keyid parameter, so verifiers match keys
// from a directory by comparing thumbprints, never by the JWK "kid" field.
package thumbprint

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// RSA returns the RFC 7638 thumbprint of an RSA public JWK. n and e are the
// base64url values exactly as they appear in the JWK.
func RSA(n, e string) string {
	return digest(fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n))
}

// OKP returns the RFC 8037 Appendix A.3 thumbprint of an OKP public JWK
// (e.g. crv "Ed25519"). x is the base64url value exactly as it appears in
// the JWK.
func OKP(crv, x string) string {
	return digest(fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, crv, x))
}

// FromJWK computes the thumbprint of a JWK given its JSON encoding. Only the
// key types used by Web Bot Auth are supported: RSA and OKP.
func FromJWK(raw []byte) (string, error) {
	var k struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", fmt.Errorf("thumbprint: invalid JWK: %w", err)
	}
	switch k.Kty {
	case "RSA":
		if k.N == "" || k.E == "" {
			return "", fmt.Errorf("thumbprint: RSA JWK missing n or e")
		}
		return RSA(k.N, k.E), nil
	case "OKP":
		if k.Crv == "" || k.X == "" {
			return "", fmt.Errorf("thumbprint: OKP JWK missing crv or x")
		}
		return OKP(k.Crv, k.X), nil
	default:
		return "", fmt.Errorf("thumbprint: unsupported kty %q", k.Kty)
	}
}

func digest(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
