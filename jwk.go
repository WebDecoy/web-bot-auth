package webbotauth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/WebDecoy/web-bot-auth/httpsig"
	"github.com/WebDecoy/web-bot-auth/thumbprint"
)

// JWK is the subset of a JSON Web Key that Web Bot Auth key directories
// publish: Ed25519 (kty OKP) and RSA public keys, with optional validity
// bounds.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Nbf int64  `json:"nbf,omitempty"`
	Exp int64  `json:"exp,omitempty"`
}

// PublicKey converts the JWK to a crypto.PublicKey (ed25519.PublicKey or
// *rsa.PublicKey).
func (k *JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("webbotauth: unsupported OKP curve %q", k.Crv)
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("webbotauth: invalid Ed25519 x: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("webbotauth: invalid Ed25519 key length %d", len(raw))
		}
		return ed25519.PublicKey(raw), nil
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("webbotauth: invalid RSA n: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("webbotauth: invalid RSA e: %w", err)
		}
		if len(n) == 0 || len(e) == 0 || len(e) > 8 {
			return nil, fmt.Errorf("webbotauth: invalid RSA key material")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil
	default:
		return nil, fmt.Errorf("webbotauth: unsupported kty %q", k.Kty)
	}
}

// Thumbprint returns the RFC 7638 / RFC 8037 base64url JWK SHA-256
// thumbprint, which Web Bot Auth uses as the signature keyid.
func (k *JWK) Thumbprint() (string, error) {
	switch k.Kty {
	case "OKP":
		return thumbprint.OKP(k.Crv, k.X), nil
	case "RSA":
		return thumbprint.RSA(k.N, k.E), nil
	default:
		return "", fmt.Errorf("webbotauth: unsupported kty %q", k.Kty)
	}
}

func (k *JWK) algorithm() (httpsig.Algorithm, error) {
	switch k.Kty {
	case "OKP":
		return httpsig.AlgEd25519, nil
	case "RSA":
		return httpsig.AlgRSAPSSSHA512, nil
	default:
		return "", fmt.Errorf("webbotauth: unsupported kty %q", k.Kty)
	}
}

// KeySet is a JWK Set as served by an HTTP Message Signatures directory.
type KeySet struct {
	Keys []JWK `json:"keys"`
}

// ParseKeySet parses a JWK Set document.
func ParseKeySet(data []byte) (*KeySet, error) {
	var s KeySet
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("webbotauth: invalid key set: %w", err)
	}
	return &s, nil
}

// resolvedKey is a directory key prepared for verification.
type resolvedKey struct {
	thumbprint string
	pub        crypto.PublicKey
	alg        httpsig.Algorithm
	nbf, exp   int64
}

// resolve converts every supported key in the set; unsupported or malformed
// keys are skipped (a directory may include key types outside this profile).
func (s *KeySet) resolve() []resolvedKey {
	out := make([]resolvedKey, 0, len(s.Keys))
	for i := range s.Keys {
		k := &s.Keys[i]
		pub, err := k.PublicKey()
		if err != nil {
			continue
		}
		tp, err := k.Thumbprint()
		if err != nil {
			continue
		}
		alg, err := k.algorithm()
		if err != nil {
			continue
		}
		out = append(out, resolvedKey{thumbprint: tp, pub: pub, alg: alg, nbf: k.Nbf, exp: k.Exp})
	}
	return out
}
