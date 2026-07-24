package httpsig

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// RFC 8941 structured-field parsing and serialization, scoped to the subset
// Web Bot Auth traffics in: dictionaries whose members are items or inner
// lists, with parameters. Parsing preserves the raw text of each dictionary
// member so signature verification can reproduce the exact bytes the signer
// covered; serialization is canonical per RFC 8941 section 4.

// Token is an RFC 8941 token bare item, kept distinct from quoted strings
// because the two serialize differently.
type Token string

// Param is a single RFC 8941 parameter. Value is one of string, Token,
// int64, float64, bool, or []byte.
type Param struct {
	Key   string
	Value any
}

// Item is an RFC 8941 item: a bare value plus parameters.
type Item struct {
	Value  any
	Params []Param
}

// InnerList is an RFC 8941 inner list: parenthesized items plus parameters.
type InnerList struct {
	Items  []Item
	Params []Param
}

// DictMember is one member of an RFC 8941 dictionary. Exactly one of Item or
// List is non-nil. Raw holds the member's value text exactly as received
// (everything after "key=", including parameters), which RFC 9421 verifiers
// need verbatim for the @signature-params line.
type DictMember struct {
	Key  string
	Item *Item
	List *InnerList
	Raw  string
}

// serializeValue renders the member's value canonically per RFC 8941.
func (m *DictMember) serializeValue() (string, error) {
	if m.List != nil {
		return serializeInnerList(*m.List)
	}
	return serializeItem(*m.Item)
}

type sfParser struct {
	s string
	i int
}

func parseDictionary(s string) ([]DictMember, error) {
	p := &sfParser{s: s}
	var members []DictMember
	p.skipSP()
	for !p.eof() {
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		m := DictMember{Key: key}
		if !p.eof() && p.peek() == '=' {
			p.i++
			start := p.i
			if !p.eof() && p.peek() == '(' {
				list, err := p.parseInnerList()
				if err != nil {
					return nil, err
				}
				m.List = &list
			} else {
				item, err := p.parseItem()
				if err != nil {
					return nil, err
				}
				m.Item = &item
			}
			m.Raw = p.s[start:p.i]
		} else {
			// Valueless member: boolean true, parameters allowed.
			params, err := p.parseParams()
			if err != nil {
				return nil, err
			}
			m.Item = &Item{Value: true, Params: params}
		}
		members = append(members, m)
		p.skipSP()
		if p.eof() {
			break
		}
		if p.peek() != ',' {
			return nil, fmt.Errorf("httpsig: expected ',' at offset %d", p.i)
		}
		p.i++
		p.skipSP()
		if p.eof() {
			return nil, fmt.Errorf("httpsig: trailing comma in dictionary")
		}
	}
	return members, nil
}

func (p *sfParser) eof() bool  { return p.i >= len(p.s) }
func (p *sfParser) peek() byte { return p.s[p.i] }

func (p *sfParser) skipSP() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.i++
	}
}

func isLCAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool   { return isLCAlpha(c) || (c >= 'A' && c <= 'Z') }

func (p *sfParser) parseKey() (string, error) {
	if p.eof() || !(isLCAlpha(p.peek()) || p.peek() == '*') {
		return "", fmt.Errorf("httpsig: invalid dictionary/parameter key at offset %d", p.i)
	}
	start := p.i
	for !p.eof() {
		c := p.peek()
		if isLCAlpha(c) || isDigit(c) || c == '_' || c == '-' || c == '.' || c == '*' {
			p.i++
			continue
		}
		break
	}
	return p.s[start:p.i], nil
}

func (p *sfParser) parseItem() (Item, error) {
	v, err := p.parseBareItem()
	if err != nil {
		return Item{}, err
	}
	params, err := p.parseParams()
	if err != nil {
		return Item{}, err
	}
	return Item{Value: v, Params: params}, nil
}

func (p *sfParser) parseInnerList() (InnerList, error) {
	if p.eof() || p.peek() != '(' {
		return InnerList{}, fmt.Errorf("httpsig: expected '(' at offset %d", p.i)
	}
	p.i++
	var list InnerList
	for {
		p.skipSP()
		if p.eof() {
			return InnerList{}, fmt.Errorf("httpsig: unterminated inner list")
		}
		if p.peek() == ')' {
			p.i++
			break
		}
		item, err := p.parseItem()
		if err != nil {
			return InnerList{}, err
		}
		list.Items = append(list.Items, item)
		if p.eof() {
			return InnerList{}, fmt.Errorf("httpsig: unterminated inner list")
		}
		if c := p.peek(); c != ' ' && c != ')' {
			return InnerList{}, fmt.Errorf("httpsig: expected space or ')' in inner list at offset %d", p.i)
		}
	}
	params, err := p.parseParams()
	if err != nil {
		return InnerList{}, err
	}
	list.Params = params
	return list, nil
}

func (p *sfParser) parseParams() ([]Param, error) {
	var params []Param
	for !p.eof() && p.peek() == ';' {
		p.i++
		p.skipSP()
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		var val any = true
		if !p.eof() && p.peek() == '=' {
			p.i++
			val, err = p.parseBareItem()
			if err != nil {
				return nil, err
			}
		}
		params = append(params, Param{Key: key, Value: val})
	}
	return params, nil
}

func (p *sfParser) parseBareItem() (any, error) {
	if p.eof() {
		return nil, fmt.Errorf("httpsig: expected bare item at end of input")
	}
	switch c := p.peek(); {
	case c == '"':
		return p.parseString()
	case c == ':':
		return p.parseByteSequence()
	case c == '?':
		return p.parseBoolean()
	case c == '-' || isDigit(c):
		return p.parseNumber()
	case isAlpha(c) || c == '*':
		return p.parseToken()
	default:
		return nil, fmt.Errorf("httpsig: invalid bare item at offset %d", p.i)
	}
}

func (p *sfParser) parseString() (string, error) {
	p.i++ // opening DQUOTE
	var b strings.Builder
	for !p.eof() {
		c := p.peek()
		p.i++
		switch {
		case c == '"':
			return b.String(), nil
		case c == '\\':
			if p.eof() {
				return "", fmt.Errorf("httpsig: unterminated escape in string")
			}
			e := p.peek()
			p.i++
			if e != '"' && e != '\\' {
				return "", fmt.Errorf("httpsig: invalid escape \\%c in string", e)
			}
			b.WriteByte(e)
		case c < 0x20 || c > 0x7e:
			return "", fmt.Errorf("httpsig: invalid character 0x%02x in string", c)
		default:
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("httpsig: unterminated string")
}

func (p *sfParser) parseByteSequence() ([]byte, error) {
	p.i++ // opening ':'
	start := p.i
	for !p.eof() && p.peek() != ':' {
		p.i++
	}
	if p.eof() {
		return nil, fmt.Errorf("httpsig: unterminated byte sequence")
	}
	enc := p.s[start:p.i]
	p.i++ // closing ':'
	if b, err := base64.StdEncoding.DecodeString(enc); err == nil {
		return b, nil
	}
	b, err := base64.RawStdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("httpsig: invalid base64 in byte sequence: %w", err)
	}
	return b, nil
}

func (p *sfParser) parseBoolean() (bool, error) {
	p.i++ // '?'
	if p.eof() {
		return false, fmt.Errorf("httpsig: unterminated boolean")
	}
	c := p.peek()
	p.i++
	switch c {
	case '1':
		return true, nil
	case '0':
		return false, nil
	default:
		return false, fmt.Errorf("httpsig: invalid boolean ?%c", c)
	}
}

func (p *sfParser) parseNumber() (any, error) {
	start := p.i
	if p.peek() == '-' {
		p.i++
	}
	digits := 0
	for !p.eof() && isDigit(p.peek()) {
		p.i++
		digits++
	}
	if digits == 0 {
		return nil, fmt.Errorf("httpsig: invalid number at offset %d", start)
	}
	if !p.eof() && p.peek() == '.' {
		p.i++
		frac := 0
		for !p.eof() && isDigit(p.peek()) {
			p.i++
			frac++
		}
		if frac == 0 || frac > 3 || digits > 12 {
			return nil, fmt.Errorf("httpsig: invalid decimal at offset %d", start)
		}
		f, err := strconv.ParseFloat(p.s[start:p.i], 64)
		if err != nil {
			return nil, fmt.Errorf("httpsig: invalid decimal: %w", err)
		}
		return f, nil
	}
	if digits > 15 {
		return nil, fmt.Errorf("httpsig: integer too long at offset %d", start)
	}
	n, err := strconv.ParseInt(p.s[start:p.i], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("httpsig: invalid integer: %w", err)
	}
	return n, nil
}

func (p *sfParser) parseToken() (Token, error) {
	start := p.i
	p.i++ // first char already validated
	for !p.eof() {
		c := p.peek()
		if isAlpha(c) || isDigit(c) || strings.IndexByte("!#$%&'*+-.^_`|~:/", c) >= 0 {
			p.i++
			continue
		}
		break
	}
	return Token(p.s[start:p.i]), nil
}

// --- canonical serialization (RFC 8941 section 4) ---

func serializeBareItem(v any) (string, error) {
	switch t := v.(type) {
	case string:
		var b strings.Builder
		b.WriteByte('"')
		for i := 0; i < len(t); i++ {
			c := t[i]
			if c < 0x20 || c > 0x7e {
				return "", fmt.Errorf("httpsig: character 0x%02x not allowed in sf-string", c)
			}
			if c == '"' || c == '\\' {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
		}
		b.WriteByte('"')
		return b.String(), nil
	case Token:
		return string(t), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	case float64:
		s := strconv.FormatFloat(t, 'f', 3, 64)
		s = strings.TrimRight(s, "0")
		if strings.HasSuffix(s, ".") {
			s += "0"
		}
		return s, nil
	case bool:
		if t {
			return "?1", nil
		}
		return "?0", nil
	case []byte:
		return ":" + base64.StdEncoding.EncodeToString(t) + ":", nil
	default:
		return "", fmt.Errorf("httpsig: cannot serialize %T as bare item", v)
	}
}

func serializeParams(params []Param) (string, error) {
	var b strings.Builder
	for _, p := range params {
		b.WriteByte(';')
		b.WriteString(p.Key)
		if v, ok := p.Value.(bool); ok && v {
			continue // boolean true parameters serialize as bare keys
		}
		s, err := serializeBareItem(p.Value)
		if err != nil {
			return "", err
		}
		b.WriteByte('=')
		b.WriteString(s)
	}
	return b.String(), nil
}

func serializeItem(item Item) (string, error) {
	v, err := serializeBareItem(item.Value)
	if err != nil {
		return "", err
	}
	p, err := serializeParams(item.Params)
	if err != nil {
		return "", err
	}
	return v + p, nil
}

func serializeInnerList(list InnerList) (string, error) {
	var b strings.Builder
	b.WriteByte('(')
	for i, item := range list.Items {
		if i > 0 {
			b.WriteByte(' ')
		}
		s, err := serializeItem(item)
		if err != nil {
			return "", err
		}
		b.WriteString(s)
	}
	b.WriteByte(')')
	p, err := serializeParams(list.Params)
	if err != nil {
		return "", err
	}
	return b.String() + p, nil
}
