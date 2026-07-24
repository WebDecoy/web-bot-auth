// Package httpsig implements the profile of HTTP Message Signatures
// (RFC 9421) used by Web Bot Auth (draft-meunier-webbotauth-httpsig-protocol):
// request signatures over derived components and header fields, with Ed25519
// and RSASSA-PSS-SHA512, structured-field dictionary member extraction, and
// verbatim @signature-params reconstruction.
//
// It is deliberately not a complete RFC 9421 implementation: response
// signing, request-response binding, Accept-Signature negotiation, and the
// HMAC/ECDSA algorithms are out of scope. See the repository README for the
// profile boundary.
package httpsig

import (
	"fmt"
	"net/http"
	"strings"
)

// Request is the message representation signatures are computed over. For
// server-side verification build one with webbotauth.RequestFromHTTP; for
// signing, from the outbound URL.
type Request struct {
	Method    string      // e.g. "GET"
	Scheme    string      // "https" or "http"
	Authority string      // host[:port], as in the Host header / URL authority
	Path      string      // URL path, leading "/"
	Query     string      // raw query including leading "?", or ""
	Header    http.Header // request header fields
}

// Component is one covered component from a Signature-Input inner list: a
// component identifier plus its parameters (e.g. key="agent2" for
// structured-field dictionary member extraction).
type Component struct {
	Name   string
	Params []Param
}

// SignatureMember is one parsed member of a Signature-Input dictionary.
// RawInput preserves the member text exactly as received; RFC 9421 requires
// the @signature-params base line to reproduce the bytes the signer covered,
// so verification uses RawInput verbatim rather than re-serializing.
type SignatureMember struct {
	Label      string
	Components []Component
	Params     []Param
	RawInput   string
}

func (m *SignatureMember) stringParam(key string) (string, bool) {
	for _, p := range m.Params {
		if p.Key == key {
			s, ok := p.Value.(string)
			return s, ok
		}
	}
	return "", false
}

func (m *SignatureMember) intParam(key string) (int64, bool) {
	for _, p := range m.Params {
		if p.Key == key {
			n, ok := p.Value.(int64)
			return n, ok
		}
	}
	return 0, false
}

// Created returns the created parameter (Unix seconds).
func (m *SignatureMember) Created() (int64, bool) { return m.intParam("created") }

// Expires returns the expires parameter (Unix seconds).
func (m *SignatureMember) Expires() (int64, bool) { return m.intParam("expires") }

// KeyID returns the keyid parameter. Web Bot Auth defines it as the
// base64url JWK SHA-256 thumbprint of the signing key.
func (m *SignatureMember) KeyID() (string, bool) { return m.stringParam("keyid") }

// Tag returns the tag parameter ("web-bot-auth" for this protocol).
func (m *SignatureMember) Tag() (string, bool) { return m.stringParam("tag") }

// Nonce returns the nonce parameter.
func (m *SignatureMember) Nonce() (string, bool) { return m.stringParam("nonce") }

// Alg returns the alg parameter if present. Web Bot Auth resolves the
// algorithm from the key type; alg, when present, must agree.
func (m *SignatureMember) Alg() (string, bool) { return m.stringParam("alg") }

// CoversComponent reports whether the member covers the named component
// (case-insensitive), with or without component parameters.
func (m *SignatureMember) CoversComponent(name string) bool {
	for _, c := range m.Components {
		if strings.EqualFold(c.Name, name) {
			return true
		}
	}
	return false
}

// ParseSignatureInput parses the value(s) of the Signature-Input header
// field into its member signatures. Multiple field lines are combined per
// RFC 9110 before parsing.
func ParseSignatureInput(values []string) ([]SignatureMember, error) {
	dict, err := parseDictionary(strings.Join(values, ", "))
	if err != nil {
		return nil, fmt.Errorf("httpsig: invalid Signature-Input: %w", err)
	}
	members := make([]SignatureMember, 0, len(dict))
	for _, d := range dict {
		if d.List == nil {
			return nil, fmt.Errorf("httpsig: Signature-Input member %q is not an inner list", d.Key)
		}
		m := SignatureMember{Label: d.Key, Params: d.List.Params, RawInput: d.Raw}
		for _, item := range d.List.Items {
			name, ok := item.Value.(string)
			if !ok {
				return nil, fmt.Errorf("httpsig: component identifier in %q is not a string", d.Key)
			}
			m.Components = append(m.Components, Component{Name: name, Params: item.Params})
		}
		members = append(members, m)
	}
	return members, nil
}

// ParseSignature parses the value(s) of the Signature header field into a
// map of label to signature bytes.
func ParseSignature(values []string) (map[string][]byte, error) {
	dict, err := parseDictionary(strings.Join(values, ", "))
	if err != nil {
		return nil, fmt.Errorf("httpsig: invalid Signature: %w", err)
	}
	sigs := make(map[string][]byte, len(dict))
	for _, d := range dict {
		if d.Item == nil {
			return nil, fmt.Errorf("httpsig: Signature member %q is not an item", d.Key)
		}
		b, ok := d.Item.Value.([]byte)
		if !ok {
			return nil, fmt.Errorf("httpsig: Signature member %q is not a byte sequence", d.Key)
		}
		sigs[d.Key] = b
	}
	return sigs, nil
}
