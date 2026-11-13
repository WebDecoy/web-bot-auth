package webbotauth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/WebDecoy/web-bot-auth/httpsig"
)

// AgentRef is one parsed Signature-Agent entry.
type AgentRef struct {
	Label string // signature label this entry applies to; "" = any (legacy form)
	URI   string // the member value exactly as sent
}

// WellKnownDirectoryPath is where an agent origin publishes its key set.
const WellKnownDirectoryPath = "/.well-known/http-message-signatures-directory"

// parseSignatureAgent parses the Signature-Agent header.
//
// draft-ietf-webbotauth-httpsig-protocol-01 §5.2.1: the header is a
// dictionary keyed by signature label whose values are https URIs, members
// MUST NOT carry parameters, and a verifier MUST ignore a member that does.
// (Draft 00 used a type parameter to pick directory, jwks_uri or cimd
// resolution; 01 removed it, so a typed member is now simply ignored.)
//
// The bare sf-string form from earlier drafts is still accepted, as §5.2.1
// allows, because deployed signers still send it.
func parseSignatureAgent(values []string) ([]AgentRef, error) {
	joined := strings.Join(values, ", ")
	if trimmed := strings.TrimSpace(joined); strings.HasPrefix(trimmed, `"`) {
		// Legacy bare sf-string form.
		uri, err := parseBareSFString(trimmed)
		if err != nil {
			return nil, err
		}
		return []AgentRef{{URI: uri}}, nil
	}
	members, err := httpsig.ParseDictionaryHeader(joined)
	if err != nil {
		return nil, fmt.Errorf("webbotauth: invalid Signature-Agent: %w", err)
	}
	refs := make([]AgentRef, 0, len(members))
	for _, m := range members {
		if m.HasParams() {
			continue
		}
		uri, ok := m.StringValue()
		if !ok {
			return nil, fmt.Errorf("webbotauth: Signature-Agent member %q is not a string", m.Key)
		}
		refs = append(refs, AgentRef{Label: m.Key, URI: uri})
	}
	return refs, nil
}

func parseBareSFString(s string) (string, error) {
	if len(s) < 2 || s[0] != '"' {
		return "", fmt.Errorf("webbotauth: invalid Signature-Agent string")
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			if strings.TrimSpace(s[i+1:]) != "" {
				return "", fmt.Errorf("webbotauth: trailing data after Signature-Agent string")
			}
			return b.String(), nil
		case c == '\\':
			i++
			if i >= len(s) || (s[i] != '"' && s[i] != '\\') {
				return "", fmt.Errorf("webbotauth: invalid escape in Signature-Agent string")
			}
			b.WriteByte(s[i])
		case c < 0x20 || c > 0x7e:
			return "", fmt.Errorf("webbotauth: invalid character in Signature-Agent string")
		default:
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("webbotauth: unterminated Signature-Agent string")
}

// refForLabel picks the Signature-Agent entry for a signature label: an
// exact label match wins, then a label-less legacy entry.
func refForLabel(refs []AgentRef, label string) (AgentRef, bool) {
	for _, r := range refs {
		if r.Label == label {
			return r, true
		}
	}
	for _, r := range refs {
		if r.Label == "" {
			return r, true
		}
	}
	return AgentRef{}, false
}

// keySetURL is the URL to fetch keys from for a Signature-Agent entry.
//
// Under draft 01 §5.5 the member value is fetched directly as a JWK Set.
// A bare origin (no path, or "/") is the form deployed signers sent under
// earlier drafts, where it meant "my well-known directory"; fetching the
// origin itself would return a web page, so that one shape still resolves
// to the well-known path. Every other URL is fetched exactly as sent.
func (r AgentRef) keySetURL() (string, error) {
	u, err := url.Parse(r.URI)
	if err != nil {
		return "", fmt.Errorf("webbotauth: invalid Signature-Agent URI %q: %w", r.URI, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("webbotauth: Signature-Agent URI %q is not https", r.URI)
	}
	if u.Host == "" || u.Opaque != "" {
		return "", fmt.Errorf("webbotauth: Signature-Agent URI %q has no host", r.URI)
	}
	if u.User != nil {
		return "", fmt.Errorf("webbotauth: Signature-Agent URI %q carries credentials", r.URI)
	}
	u.Fragment, u.RawFragment = "", ""
	if (u.Path == "" || u.Path == "/") && u.RawQuery == "" && !u.ForceQuery {
		return "https://" + u.Host + WellKnownDirectoryPath, nil
	}
	return u.String(), nil
}

// ResolveSignatureAgent maps one Signature-Agent member value to the URL a
// verifier fetches and the identifier draft 01 assigns it. It is the single
// definition other implementations (edge and SDK ports) test against; see
// testdata/signature_agent_resolution.json.
func ResolveSignatureAgent(value string) (fetch, identifier string, err error) {
	fetch, err = AgentRef{URI: value}.keySetURL()
	if err != nil {
		return "", "", err
	}
	identifier, err = AgentIdentifier(fetch)
	if err != nil {
		return "", "", err
	}
	return fetch, identifier, nil
}

// AgentIdentifier is the identifier draft 01 assigns to a resolved key set:
// the URL the verifier fetched, query discarded (§5.5), normalized per
// RFC 3986 §6.2.2 and §6.2.3 so that spellings of one URL compare equal.
func AgentIdentifier(fetched string) (string, error) {
	u, err := url.Parse(fetched)
	if err != nil {
		return "", err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Scheme == "https" {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}
	u.RawQuery, u.ForceQuery = "", false
	u.Fragment, u.RawFragment = "", ""
	if u.Path == "" {
		u.Path, u.RawPath = "/", ""
	}
	// Remove dot segments without touching the escaping.
	u = u.ResolveReference(&url.URL{})
	u.RawPath = upperPercentHex(u.EscapedPath())
	return u.String(), nil
}

func upperPercentHex(p string) string {
	b := []byte(p)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = toUpperHex(b[i+1])
			b[i+2] = toUpperHex(b[i+2])
		}
	}
	return string(b)
}

func toUpperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}
