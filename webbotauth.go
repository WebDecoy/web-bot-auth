// Package webbotauth verifies and produces Web Bot Auth signatures —
// cryptographic bot identity for HTTP requests per
// draft-meunier-webbotauth-httpsig-protocol (RFC 9421 HTTP Message
// Signatures with the "web-bot-auth" tag, keyed by JWK thumbprint, with
// keys discovered from HTTP Message Signatures directories).
//
// A zero-dependency Go implementation, cross-validated against the
// cloudflare/web-bot-auth reference test vectors.
package webbotauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/WebDecoy/web-bot-auth/httpsig"
)

// Tag is the RFC 9421 tag parameter value that marks a Web Bot Auth
// signature.
const Tag = "web-bot-auth"

// Status classifies the outcome of verifying a request.
type Status int

const (
	// StatusNoSignature: the request carries no Web Bot Auth signature.
	// Plain traffic — the request simply isn't claiming an agent identity.
	StatusNoSignature Status = iota
	// StatusVerified: at least one Web Bot Auth signature verified against
	// a resolvable key.
	StatusVerified
	// StatusInvalid: the request claims a Web Bot Auth signature but no
	// candidate verified (bad signature, expired, unknown key, malformed
	// headers). For detection purposes this is the interesting outcome.
	StatusInvalid
)

func (s Status) String() string {
	switch s {
	case StatusVerified:
		return "verified"
	case StatusInvalid:
		return "invalid"
	default:
		return "no-signature"
	}
}

// Result reports what verification found.
type Result struct {
	Status Status

	// Populated when Status is StatusVerified.
	Label     string            // signature label that verified
	KeyID     string            // JWK thumbprint of the verifying key
	Algorithm httpsig.Algorithm // algorithm that verified
	Agent     string            // Signature-Agent URI for the verified label, if any
	Directory string            // URL keys were resolved from ("" when static keys matched)
	Created   time.Time
	Expires   time.Time
	Nonce     string

	// Diagnostics. Signatures counts Web Bot Auth candidates seen; Errors
	// collects per-candidate failures when Status is StatusInvalid.
	Signatures int
	Errors     []error
}

// Verifier verifies Web Bot Auth requests. Construct with NewVerifier; safe
// for concurrent use.
type Verifier struct {
	static      []resolvedKey
	directories *directoryClient
	clock       func() time.Time
	skew        time.Duration
	maxLifetime time.Duration
	nonceCheck  func(ctx context.Context, nonce string, r *Result) error
}

// Option configures a Verifier.
type Option func(*verifierConfig)

type verifierConfig struct {
	static      []JWK
	allowlist   []string
	open        bool
	httpClient  *http.Client
	cacheTTL    time.Duration
	staleTTL    time.Duration
	clock       func() time.Time
	skew        time.Duration
	maxLifetime time.Duration
	nonceCheck  func(ctx context.Context, nonce string, r *Result) error
}

// WithKeys adds static keys matched by thumbprint before any directory
// fetch. Useful for pinned agents and tests.
func WithKeys(keys ...JWK) Option {
	return func(c *verifierConfig) { c.static = append(c.static, keys...) }
}

// WithDirectoryAllowlist permits directory fetches from these hostnames.
// Entries are exact hostnames, or ".example.com" to allow a domain's
// subdomains. Without an allowlist (and without WithOpenDirectories) no
// directory is ever fetched and only static keys can verify.
func WithDirectoryAllowlist(hosts ...string) Option {
	return func(c *verifierConfig) { c.allowlist = append(c.allowlist, hosts...) }
}

// WithOpenDirectories permits fetching any https directory the request
// names. The default fetch client refuses loopback, private, and link-local
// addresses; combine with your own network policy before enabling in
// sensitive environments.
func WithOpenDirectories() Option {
	return func(c *verifierConfig) { c.open = true }
}

// WithHTTPClient replaces the directory fetch client. The caller then owns
// SSRF policy: the built-in non-global address guard applies only to the
// default client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *verifierConfig) { c.httpClient = hc }
}

// WithCacheTTL sets how long fetched directories are served from cache, and
// how long stale entries may be served when a refresh fails.
func WithCacheTTL(ttl, stale time.Duration) Option {
	return func(c *verifierConfig) { c.cacheTTL, c.staleTTL = ttl, stale }
}

// WithClock replaces the time source (tests, replayed traffic).
func WithClock(now func() time.Time) Option {
	return func(c *verifierConfig) { c.clock = now }
}

// WithClockSkew sets the tolerance applied to created/expires checks.
// Default 10 seconds.
func WithClockSkew(d time.Duration) Option {
	return func(c *verifierConfig) { c.skew = d }
}

// WithMaxLifetime caps expires-created. The draft recommends signatures live
// at most 24 hours; that is the default.
func WithMaxLifetime(d time.Duration) Option {
	return func(c *verifierConfig) { c.maxLifetime = d }
}

// WithNonceChecker installs a replay policy: called with each otherwise-valid
// signature's nonce; returning an error rejects the candidate.
func WithNonceChecker(f func(ctx context.Context, nonce string, r *Result) error) Option {
	return func(c *verifierConfig) { c.nonceCheck = f }
}

// NewVerifier builds a Verifier.
func NewVerifier(opts ...Option) *Verifier {
	cfg := verifierConfig{
		cacheTTL:    defaultCacheTTL,
		staleTTL:    defaultStaleTTL,
		clock:       time.Now,
		skew:        10 * time.Second,
		maxLifetime: 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	v := &Verifier{
		static:      (&KeySet{Keys: cfg.static}).resolve(),
		clock:       cfg.clock,
		skew:        cfg.skew,
		maxLifetime: cfg.maxLifetime,
		nonceCheck:  cfg.nonceCheck,
	}
	v.directories = newDirectoryClient(cfg.httpClient, cfg.cacheTTL, cfg.staleTTL, cfg.allowlist, cfg.open, cfg.clock)
	return v
}

// RequestOption adjusts RequestFromHTTP.
type RequestOption func(*httpsig.Request)

// WithScheme overrides the scheme inferred from the connection — needed
// behind a TLS-terminating proxy, where r.TLS is nil but the client signed
// an https target URI.
func WithScheme(scheme string) RequestOption {
	return func(r *httpsig.Request) { r.Scheme = scheme }
}

// RequestFromHTTP adapts an inbound *http.Request for verification.
func RequestFromHTTP(r *http.Request, opts ...RequestOption) *httpsig.Request {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	req := &httpsig.Request{
		Method:    r.Method,
		Scheme:    scheme,
		Authority: r.Host,
		Path:      r.URL.EscapedPath(),
		Query:     query,
		Header:    r.Header,
	}
	for _, opt := range opts {
		opt(req)
	}
	return req
}

// Verify checks an inbound request for Web Bot Auth signatures. It never
// returns an error for untrusted input — every failure mode is a Result;
// treat StatusInvalid as a detection signal, not a transport error.
func (v *Verifier) Verify(ctx context.Context, req *httpsig.Request) *Result {
	res := &Result{}

	sigInput := req.Header.Values("Signature-Input")
	sigHeader := req.Header.Values("Signature")
	if len(sigInput) == 0 && len(sigHeader) == 0 {
		return res
	}
	if len(sigInput) == 0 || len(sigHeader) == 0 {
		res.Status = StatusInvalid
		res.Errors = append(res.Errors, errors.New("webbotauth: Signature and Signature-Input must both be present"))
		return res
	}

	members, err := httpsig.ParseSignatureInput(sigInput)
	if err != nil {
		res.Status = StatusInvalid
		res.Errors = append(res.Errors, err)
		return res
	}
	sigs, err := httpsig.ParseSignature(sigHeader)
	if err != nil {
		res.Status = StatusInvalid
		res.Errors = append(res.Errors, err)
		return res
	}

	agentValues := req.Header.Values("Signature-Agent")
	var agents []AgentRef
	if len(agentValues) > 0 {
		agents, err = parseSignatureAgent(agentValues)
		if err != nil {
			res.Status = StatusInvalid
			res.Errors = append(res.Errors, err)
			return res
		}
	}

	for i := range members {
		m := &members[i]
		if tag, ok := m.Tag(); !ok || tag != Tag {
			continue
		}
		res.Signatures++
		if err := v.verifyCandidate(ctx, req, m, sigs, agents, len(agentValues) > 0, res); err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("%s: %w", m.Label, err))
			continue
		}
		res.Status = StatusVerified
		res.Errors = nil
		return res
	}

	if res.Signatures > 0 {
		res.Status = StatusInvalid
	}
	return res
}

func (v *Verifier) verifyCandidate(ctx context.Context, req *httpsig.Request, m *httpsig.SignatureMember, sigs map[string][]byte, agents []AgentRef, agentHeaderPresent bool, res *Result) error {
	sig, ok := sigs[m.Label]
	if !ok {
		return errors.New("no matching Signature member")
	}

	created, ok := m.Created()
	if !ok {
		return errors.New("missing created parameter")
	}
	expires, ok := m.Expires()
	if !ok {
		return errors.New("missing expires parameter")
	}
	keyID, ok := m.KeyID()
	if !ok || keyID == "" {
		return errors.New("missing keyid parameter")
	}

	now := v.clock()
	if now.Add(v.skew).Before(time.Unix(created, 0)) {
		return errors.New("signature created in the future")
	}
	if now.After(time.Unix(expires, 0).Add(v.skew)) {
		return errors.New("signature expired")
	}
	if lifetime := time.Unix(expires, 0).Sub(time.Unix(created, 0)); lifetime > v.maxLifetime {
		return fmt.Errorf("signature lifetime %s exceeds maximum %s", lifetime, v.maxLifetime)
	}

	if !m.CoversComponent("@authority") && !m.CoversComponent("@target-uri") {
		return errors.New("signature covers neither @authority nor @target-uri")
	}
	if agentHeaderPresent && !m.CoversComponent("signature-agent") {
		return errors.New("Signature-Agent header present but not covered by the signature")
	}

	base, err := httpsig.SignatureBase(req, m)
	if err != nil {
		return err
	}

	alg, _ := m.Alg()
	key, directory, agentURI, err := v.resolveKey(ctx, keyID, m.Label, agents)
	if err != nil {
		return err
	}
	if alg != "" && alg != string(key.alg) {
		return fmt.Errorf("alg parameter %q does not match key type algorithm %q", alg, key.alg)
	}
	if key.nbf != 0 && now.Before(time.Unix(key.nbf, 0)) {
		return errors.New("directory key not yet valid")
	}
	if key.exp != 0 && now.After(time.Unix(key.exp, 0)) {
		return errors.New("directory key expired")
	}

	if err := httpsig.VerifySignature(key.pub, key.alg, base, sig); err != nil {
		return err
	}

	nonce, _ := m.Nonce()
	res.Label = m.Label
	res.KeyID = keyID
	res.Algorithm = key.alg
	res.Agent = agentURI
	res.Directory = directory
	res.Created = time.Unix(created, 0)
	res.Expires = time.Unix(expires, 0)
	res.Nonce = nonce

	if v.nonceCheck != nil {
		if err := v.nonceCheck(ctx, nonce, res); err != nil {
			return fmt.Errorf("nonce rejected: %w", err)
		}
	}
	return nil
}

func (v *Verifier) resolveKey(ctx context.Context, keyID, label string, agents []AgentRef) (resolvedKey, string, string, error) {
	for _, k := range v.static {
		if k.thumbprint == keyID {
			return k, "", "", nil
		}
	}
	ref, ok := refForLabel(agents, label)
	if !ok {
		return resolvedKey{}, "", "", errors.New("key not in static set and no Signature-Agent to resolve from")
	}
	dirURL, err := ref.keySetURL()
	if err != nil {
		return resolvedKey{}, "", "", err
	}
	keys, err := v.directories.keys(ctx, dirURL)
	if err != nil {
		return resolvedKey{}, "", "", err
	}
	for _, k := range keys {
		if k.thumbprint == keyID {
			return k, dirURL, ref.URI, nil
		}
	}
	return resolvedKey{}, "", "", fmt.Errorf("keyid %q not found in directory %s", keyID, dirURL)
}
