package httpsig

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"io"
)

// Algorithm names an HTTP signature algorithm from the RFC 9421 registry.
// The Web Bot Auth profile supports the two algorithms exercised by the
// protocol's test vectors.
type Algorithm string

const (
	AlgEd25519      Algorithm = "ed25519"
	AlgRSAPSSSHA512 Algorithm = "rsa-pss-sha512"
)

// VerifySignature checks sig over base with the given public key.
// Supported key types: ed25519.PublicKey and *rsa.PublicKey.
func VerifySignature(pub crypto.PublicKey, alg Algorithm, base, sig []byte) error {
	switch alg {
	case AlgEd25519:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("httpsig: algorithm %s requires an Ed25519 key, got %T", alg, pub)
		}
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("httpsig: invalid Ed25519 key length %d", len(key))
		}
		if !ed25519.Verify(key, base, sig) {
			return fmt.Errorf("httpsig: ed25519 signature verification failed")
		}
		return nil
	case AlgRSAPSSSHA512:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("httpsig: algorithm %s requires an RSA key, got %T", alg, pub)
		}
		digest := sha512.Sum512(base)
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA512}
		if err := rsa.VerifyPSS(key, crypto.SHA512, digest[:], sig, opts); err != nil {
			return fmt.Errorf("httpsig: rsa-pss signature verification failed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("httpsig: unsupported algorithm %q", alg)
	}
}

// SignBase signs base with the given private key. Supported key types:
// ed25519.PrivateKey and *rsa.PrivateKey. RSA-PSS uses a salt length equal
// to the SHA-512 digest length, per RFC 9421 section 3.3.1.
func SignBase(rand io.Reader, priv crypto.PrivateKey, alg Algorithm, base []byte) ([]byte, error) {
	switch alg {
	case AlgEd25519:
		key, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("httpsig: algorithm %s requires an Ed25519 private key, got %T", alg, priv)
		}
		return ed25519.Sign(key, base), nil
	case AlgRSAPSSSHA512:
		key, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("httpsig: algorithm %s requires an RSA private key, got %T", alg, priv)
		}
		digest := sha512.Sum512(base)
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}
		return rsa.SignPSS(rand, key, crypto.SHA512, digest[:], opts)
	default:
		return nil, fmt.Errorf("httpsig: unsupported algorithm %q", alg)
	}
}
