package webbotauth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/WebDecoy/web-bot-auth/httpsig"
)

// AgentRefType is the discovery mechanism a Signature-Agent member declares.
type AgentRefType string

const (
	// AgentRefDirectory resolves keys at the agent origin's well-known
	// HTTP Message Signatures directory. This is the default.
	AgentRefDirectory AgentRefType = "directory"
	// AgentRefJWKSURI points directly at a JWK Set URL.
	AgentRefJWKSURI AgentRefType = "jwks_uri"
	// AgentRefCIMD points at a Client ID Metadata Document. Recognized but
	// not resolved by this package.
	AgentRefCIMD AgentRefType = "cimd"
)

// AgentRef is one parsed Signature-Agent entry.
type AgentRef struct {
	Label string // signature label this entry applies to; "" = any (legacy form)
	URI   string
	Type  AgentRefType
}

// WellKnownDirectoryPath is where an agent origin publishes its key set.
const WellKnownDirectoryPath = "/.well-known/http-message-signatures-directory"

// parseSignatureAgent parses the Signature-Agent header. The current draft
// form is a structured-field dictionary keyed by signature label with an
// optional type parameter; the earlier architecture draft used a bare
// sf-string that applies to any signature, which deployed signers still
// send, so both forms are accepted.
func parseSignatureAgent(values []string) ([]AgentRef, error) {
	joined := strings.Join(values, ", ")
	if trimmed := strings.TrimSpace(joined); strings.HasPrefix(trimmed, `"`) {
		// Legacy bare sf-string form.
		uri, err := parseBareSFString(trimmed)
		if err != nil {
			return nil, err
		}
		return []AgentRef{{URI: uri, Type: AgentRefDirectory}}, nil
	}
	members, err := httpsig.ParseDictionaryHeader(joined)
	if err != nil {
		return nil, fmt.Errorf("webbotauth: invalid Signature-Agent: %w", err)
	}
	refs := make([]AgentRef, 0, len(members))
	for _, m := range members {
		uri, ok := m.StringValue()
		if !ok {
			return nil, fmt.Errorf("webbotauth: Signature-Agent member %q is not a string", m.Key)
		}
		ref := AgentRef{Label: m.Key, URI: uri, Type: AgentRefDirectory}
		if t, ok := m.Param("type"); ok {
			switch AgentRefType(t) {
			case AgentRefDirectory, AgentRefJWKSURI, AgentRefCIMD:
				ref.Type = AgentRefType(t)
			default:
				return nil, fmt.Errorf("webbotauth: unknown Signature-Agent type %q", t)
			}
		}
		refs = append(refs, ref)
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

// keySetURL derives the URL to fetch keys from for a Signature-Agent entry.
func (r AgentRef) keySetURL() (string, error) {
	u, err := url.Parse(r.URI)
	if err != nil {
		return "", fmt.Errorf("webbotauth: invalid Signature-Agent URI %q: %w", r.URI, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("webbotauth: Signature-Agent URI %q is not https", r.URI)
	}
	if u.Host == "" {
		return "", fmt.Errorf("webbotauth: Signature-Agent URI %q has no host", r.URI)
	}
	switch r.Type {
	case AgentRefDirectory:
		return "https://" + u.Host + WellKnownDirectoryPath, nil
	case AgentRefJWKSURI:
		return u.String(), nil
	default:
		return "", fmt.Errorf("webbotauth: Signature-Agent type %q is not resolvable", r.Type)
	}
}
