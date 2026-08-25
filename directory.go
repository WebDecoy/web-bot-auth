package webbotauth

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Key directories are fetched from URLs supplied by the *request under
// verification*, so the client treats every fetch as an SSRF vector: https
// only, an optional host allowlist, a guarded dialer that refuses non-global
// addresses, capped response size, and re-validation on every redirect hop.

const (
	defaultCacheTTL     = 1 * time.Hour
	defaultStaleTTL     = 24 * time.Hour
	defaultFetchTimeout = 10 * time.Second
	maxDirectoryBytes   = 1 << 20 // 1 MiB
	maxRedirects        = 3
)

type directoryClient struct {
	hc        *http.Client
	ttl       time.Duration
	staleTTL  time.Duration
	allowlist []string // empty + open=false → all directory fetches refused
	open      bool
	now       func() time.Time

	mu    sync.Mutex
	cache map[string]*directoryEntry
}

type directoryEntry struct {
	keys    []resolvedKey
	fetched time.Time
}

func newDirectoryClient(hc *http.Client, ttl, staleTTL time.Duration, allowlist []string, open bool, now func() time.Time) *directoryClient {
	if hc == nil {
		hc = guardedHTTPClient(open)
	}
	return &directoryClient{
		hc:        hc,
		ttl:       ttl,
		staleTTL:  staleTTL,
		allowlist: allowlist,
		open:      open,
		now:       now,
		cache:     make(map[string]*directoryEntry),
	}
}

// guardedHTTPClient builds the default fetch client. In open mode the dialer
// refuses loopback, private, link-local, and unspecified addresses so a
// hostile Signature-Agent URI cannot point the verifier at internal
// infrastructure.
func guardedHTTPClient(open bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if open {
		dialer.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("webbotauth: cannot parse dial address %q", host)
			}
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return fmt.Errorf("webbotauth: refusing to dial non-global address %s", ip)
			}
			return nil
		}
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: defaultFetchTimeout}
}

func (d *directoryClient) permitted(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("webbotauth: invalid directory URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("webbotauth: directory URL %q is not https", rawURL)
	}
	host := strings.ToLower(u.Hostname())
	for _, allowed := range d.allowlist {
		allowed = strings.ToLower(allowed)
		if host == allowed {
			return nil
		}
		if strings.HasPrefix(allowed, ".") && strings.HasSuffix(host, allowed) {
			return nil
		}
	}
	if d.open {
		return nil
	}
	return fmt.Errorf("webbotauth: directory host %q is not on the allowlist", host)
}

func (d *directoryClient) keys(ctx context.Context, rawURL string) ([]resolvedKey, error) {
	if err := d.permitted(rawURL); err != nil {
		return nil, err
	}
	now := d.now()

	d.mu.Lock()
	entry := d.cache[rawURL]
	if entry != nil && now.Sub(entry.fetched) < d.ttl {
		keys := entry.keys
		d.mu.Unlock()
		return keys, nil
	}
	d.mu.Unlock()

	keys, err := d.fetch(ctx, rawURL)
	if err != nil {
		// Serve stale on fetch failure, bounded by staleTTL.
		d.mu.Lock()
		defer d.mu.Unlock()
		if entry != nil && now.Sub(entry.fetched) < d.staleTTL {
			return entry.keys, nil
		}
		return nil, err
	}

	d.mu.Lock()
	d.cache[rawURL] = &directoryEntry{keys: keys, fetched: now}
	d.mu.Unlock()
	return keys, nil
}

func (d *directoryClient) fetch(ctx context.Context, rawURL string) ([]resolvedKey, error) {
	current := rawURL
	for hop := 0; ; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return nil, fmt.Errorf("webbotauth: directory request: %w", err)
		}
		req.Header.Set("Accept", "application/http-message-signatures-directory+json, application/jwk-set+json, application/json")

		// Redirects are followed manually so each hop re-passes the policy
		// check; a compliant allowlisted host must not be able to bounce the
		// verifier to an arbitrary URL.
		hc := *d.hc
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("webbotauth: directory fetch %q: %w", current, err)
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if hop >= maxRedirects {
				return nil, fmt.Errorf("webbotauth: too many directory redirects from %q", rawURL)
			}
			next, err := url.Parse(loc)
			if err != nil {
				return nil, fmt.Errorf("webbotauth: invalid directory redirect: %w", err)
			}
			base, _ := url.Parse(current)
			current = base.ResolveReference(next).String()
			if err := d.permitted(current); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("webbotauth: directory %q returned %d", current, resp.StatusCode)
		}
		if err := checkDirectoryContentType(resp.Header.Get("Content-Type")); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("webbotauth: directory %q: %w", current, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectoryBytes+1))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("webbotauth: reading directory %q: %w", current, err)
		}
		if int64(len(body)) > maxDirectoryBytes {
			return nil, fmt.Errorf("webbotauth: directory %q exceeds %d bytes", current, maxDirectoryBytes)
		}
		set, err := ParseKeySet(body)
		if err != nil {
			return nil, err
		}
		return set.resolve(), nil
	}
}

// directoryContentTypes are the media types a key directory may arrive as.
//
// draft-meunier-webbotauth-httpsig-protocol-02 §5.5.1 requires the well-known
// directory to be served as application/http-message-signatures-directory+json.
// The other two are accepted because they are what this client asks for in its
// Accept header and what deployments predating the registration actually send;
// refusing them would fail against live directories to enforce a MUST that
// binds the server, not us.
var directoryContentTypes = map[string]bool{
	"application/http-message-signatures-directory+json": true,
	"application/jwk-set+json":                           true,
	"application/json":                                   true,
}

// checkDirectoryContentType rejects a response that is plainly not a directory.
//
// Without this the client parsed whatever came back and only failed if the
// bytes were not JSON. A captive portal, an SSO interstitial or an error page
// that happens to be JSON would be read as a key set, and the verifier would
// then report "no key matching keyid" — a statement about the operator's
// directory, when the truth was that we never reached one.
//
// An absent Content-Type is allowed. It is a server omission rather than a
// wrong answer, and the JWKS parse still has to succeed.
func checkDirectoryContentType(header string) error {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil {
		return fmt.Errorf("unparseable Content-Type %q", header)
	}
	if !directoryContentTypes[strings.ToLower(mediaType)] {
		return fmt.Errorf("Content-Type %q is not a key directory", mediaType)
	}
	return nil
}
