package httpsig

import (
	"fmt"
	"strings"
)

// SignatureBase constructs the RFC 9421 signature base (section 2.5) for one
// signature member over the given request. The @signature-params line uses
// the member's raw Signature-Input text verbatim, reproducing exactly what
// the signer covered.
func SignatureBase(req *Request, m *SignatureMember) ([]byte, error) {
	var b strings.Builder
	for i := range m.Components {
		c := &m.Components[i]
		id, err := serializeComponentID(c)
		if err != nil {
			return nil, err
		}
		val, err := componentValue(req, c)
		if err != nil {
			return nil, err
		}
		b.WriteString(id)
		b.WriteString(": ")
		b.WriteString(val)
		b.WriteByte('\n')
	}
	b.WriteString(`"@signature-params": `)
	b.WriteString(strings.TrimSpace(m.RawInput))
	return []byte(b.String()), nil
}

func serializeComponentID(c *Component) (string, error) {
	id, err := serializeBareItem(strings.ToLower(c.Name))
	if err != nil {
		return "", err
	}
	params, err := serializeParams(c.Params)
	if err != nil {
		return "", err
	}
	return id + params, nil
}

func componentValue(req *Request, c *Component) (string, error) {
	name := strings.ToLower(c.Name)
	if strings.HasPrefix(name, "@") {
		if len(c.Params) > 0 {
			return "", fmt.Errorf("httpsig: parameters on derived component %s are not supported", name)
		}
		return derivedComponent(req, name)
	}
	// Header field component. The only component parameter in the Web Bot
	// Auth profile is key="..." (RFC 9421 section 2.1.2: structured-field
	// dictionary member extraction), used for Signature-Agent.
	var dictKey string
	for _, p := range c.Params {
		if p.Key != "key" {
			return "", fmt.Errorf("httpsig: component parameter %q on %q is not supported", p.Key, name)
		}
		s, ok := p.Value.(string)
		if !ok {
			return "", fmt.Errorf("httpsig: key parameter on %q must be a string", name)
		}
		dictKey = s
	}
	values := req.Header.Values(name)
	if len(values) == 0 {
		return "", fmt.Errorf("httpsig: covered header %q not present in request", name)
	}
	if dictKey != "" {
		return dictMemberValue(values, name, dictKey)
	}
	return canonicalFieldValue(values), nil
}

// canonicalFieldValue combines field lines per RFC 9421 section 2.1: each
// value has leading/trailing whitespace stripped and internal whitespace
// runs collapsed to a single space, then values join with ", ".
func canonicalFieldValue(values []string) string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.Join(strings.Fields(v), " ")
	}
	return strings.Join(out, ", ")
}

func dictMemberValue(values []string, header, key string) (string, error) {
	dict, err := parseDictionary(strings.Join(values, ", "))
	if err != nil {
		return "", fmt.Errorf("httpsig: header %q is not a valid dictionary: %w", header, err)
	}
	for i := range dict {
		if dict[i].Key == key {
			return dict[i].serializeValue()
		}
	}
	return "", fmt.Errorf("httpsig: header %q has no dictionary member %q", header, key)
}

func derivedComponent(req *Request, name string) (string, error) {
	switch name {
	case "@method":
		return strings.ToUpper(req.Method), nil
	case "@authority":
		return canonicalAuthority(req), nil
	case "@scheme":
		return strings.ToLower(req.Scheme), nil
	case "@target-uri":
		return strings.ToLower(req.Scheme) + "://" + canonicalAuthority(req) + req.Path + req.Query, nil
	case "@path":
		return req.Path, nil
	case "@query":
		if req.Query == "" {
			return "?", nil
		}
		return req.Query, nil
	case "@request-target":
		return req.Path + req.Query, nil
	default:
		return "", fmt.Errorf("httpsig: derived component %s is not supported", name)
	}
}

// canonicalAuthority lowercases the authority and drops the port when it is
// the default for the scheme, matching URI normalization (RFC 3986) and the
// reference implementation.
func canonicalAuthority(req *Request) string {
	authority := strings.ToLower(req.Authority)
	switch strings.ToLower(req.Scheme) {
	case "https":
		authority = strings.TrimSuffix(authority, ":443")
	case "http":
		authority = strings.TrimSuffix(authority, ":80")
	}
	return authority
}
