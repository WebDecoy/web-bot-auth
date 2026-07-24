package webbotauth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/WebDecoy/web-bot-auth/httpsig"
)

// Signer produces Web Bot Auth signatures on outbound requests — for
// operating a signing bot, and for tests. The zero value is not usable;
// construct with NewSigner.
type Signer struct {
	key      crypto.PrivateKey
	alg      httpsig.Algorithm
	keyID    string
	agent    string // Signature-Agent URI; "" omits the header
	label    string
	lifetime time.Duration
	clock    func() time.Time
}

// SignerOption configures a Signer.
type SignerOption func(*Signer)

// WithSignatureAgent sets the Signature-Agent URI advertised (and covered)
// by signatures, typically the https origin publishing the bot's key
// directory.
func WithSignatureAgent(uri string) SignerOption {
	return func(s *Signer) { s.agent = uri }
}

// WithLabel sets the signature label (default "sig1").
func WithLabel(label string) SignerOption {
	return func(s *Signer) { s.label = label }
}

// WithLifetime sets how long signatures are valid (default 10 minutes,
// maximum 24 hours per the draft's recommendation).
func WithLifetime(d time.Duration) SignerOption {
	return func(s *Signer) { s.lifetime = d }
}

// WithSignerClock replaces the time source (tests).
func WithSignerClock(now func() time.Time) SignerOption {
	return func(s *Signer) { s.clock = now }
}

// NewSigner builds a Signer from an Ed25519 or RSA private key. The keyid is
// derived from the public key's JWK thumbprint, as the protocol requires.
func NewSigner(key crypto.PrivateKey, opts ...SignerOption) (*Signer, error) {
	s := &Signer{
		key:      key,
		label:    "sig1",
		lifetime: 10 * time.Minute,
		clock:    time.Now,
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		s.alg = httpsig.AlgEd25519
		pub := k.Public().(ed25519.PublicKey)
		jwk := JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
		tp, err := jwk.Thumbprint()
		if err != nil {
			return nil, err
		}
		s.keyID = tp
	case *rsa.PrivateKey:
		s.alg = httpsig.AlgRSAPSSSHA512
		pub := k.Public().(*rsa.PublicKey)
		jwk := JWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(bigEndianInt(pub.E)),
		}
		tp, err := jwk.Thumbprint()
		if err != nil {
			return nil, err
		}
		s.keyID = tp
	default:
		return nil, fmt.Errorf("webbotauth: unsupported private key type %T", key)
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.lifetime <= 0 || s.lifetime > 24*time.Hour {
		return nil, fmt.Errorf("webbotauth: signature lifetime must be within (0, 24h]")
	}
	return s, nil
}

// PublicJWK returns the signer's public key as a JWK, ready to publish in an
// HTTP Message Signatures directory.
func (s *Signer) PublicJWK() JWK {
	switch k := s.key.(type) {
	case ed25519.PrivateKey:
		pub := k.Public().(ed25519.PublicKey)
		return JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
	case *rsa.PrivateKey:
		pub := k.Public().(*rsa.PublicKey)
		return JWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(bigEndianInt(pub.E)),
		}
	}
	return JWK{}
}

// SignRequest signs an outbound *http.Request in place, setting the
// Signature-Input, Signature, and (when configured) Signature-Agent headers.
func (s *Signer) SignRequest(r *http.Request) error {
	if r.URL == nil {
		return fmt.Errorf("webbotauth: request has no URL")
	}
	target := *r.URL
	if target.Host == "" {
		target.Host = r.Host
	}
	if target.Scheme == "" {
		target.Scheme = "https"
	}
	query := ""
	if target.RawQuery != "" {
		query = "?" + target.RawQuery
	}
	req := &httpsig.Request{
		Method:    r.Method,
		Scheme:    target.Scheme,
		Authority: target.Host,
		Path:      target.EscapedPath(),
		Query:     query,
		Header:    r.Header,
	}

	if s.agent != "" {
		r.Header.Set("Signature-Agent", s.label+"="+quoteSFString(s.agent))
	}

	nonce := make([]byte, 64)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("webbotauth: generating nonce: %w", err)
	}
	now := s.clock()

	components := []string{"@authority"}
	if s.agent != "" {
		components = append(components, "signature-agent")
	}
	memberValue := buildSignatureInputMember(components, now.Unix(), now.Add(s.lifetime).Unix(), s.keyID, string(s.alg), base64.StdEncoding.EncodeToString(nonce))

	// Parse our own member back so signing and verification share the same
	// base-construction path.
	members, err := httpsig.ParseSignatureInput([]string{s.label + "=" + memberValue})
	if err != nil {
		return fmt.Errorf("webbotauth: internal: %w", err)
	}
	base, err := httpsig.SignatureBase(req, &members[0])
	if err != nil {
		return err
	}
	sig, err := httpsig.SignBase(rand.Reader, s.key, s.alg, base)
	if err != nil {
		return err
	}

	r.Header.Set("Signature-Input", s.label+"="+memberValue)
	r.Header.Set("Signature", s.label+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

// buildSignatureInputMember serializes the inner list for Signature-Input,
// with the parameter order the reference implementation emits.
func buildSignatureInputMember(components []string, created, expires int64, keyID, alg, nonce string) string {
	quoted := make([]string, len(components))
	for i, c := range components {
		quoted[i] = quoteSFString(c)
	}
	return fmt.Sprintf("(%s);created=%d;keyid=%s;alg=%s;expires=%d;nonce=%s;tag=%s",
		strings.Join(quoted, " "), created, quoteSFString(keyID), quoteSFString(alg),
		expires, quoteSFString(nonce), quoteSFString(Tag))
}

func quoteSFString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String()
}

func bigEndianInt(n int) []byte {
	var buf [8]byte
	for i := 7; i >= 0; i-- {
		buf[i] = byte(n)
		n >>= 8
	}
	out := buf[:]
	for len(out) > 1 && out[0] == 0 {
		out = out[1:]
	}
	return out
}
