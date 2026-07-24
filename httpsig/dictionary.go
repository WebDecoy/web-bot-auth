package httpsig

// DictionaryMember is a public view of one member of a structured-field
// dictionary header, for callers that need to inspect headers like
// Signature-Agent without touching the parser internals.
type DictionaryMember struct {
	Key    string
	item   *Item
	params []Param
}

// ParseDictionaryHeader parses a structured-field dictionary header value.
func ParseDictionaryHeader(value string) ([]DictionaryMember, error) {
	dict, err := parseDictionary(value)
	if err != nil {
		return nil, err
	}
	out := make([]DictionaryMember, 0, len(dict))
	for _, d := range dict {
		m := DictionaryMember{Key: d.Key}
		if d.Item != nil {
			m.item = d.Item
			m.params = d.Item.Params
		} else {
			m.params = d.List.Params
		}
		out = append(out, m)
	}
	return out, nil
}

// StringValue returns the member's value when it is an sf-string.
func (m *DictionaryMember) StringValue() (string, bool) {
	if m.item == nil {
		return "", false
	}
	s, ok := m.item.Value.(string)
	return s, ok
}

// Param returns the named parameter's value as text when it is a string or
// token.
func (m *DictionaryMember) Param(key string) (string, bool) {
	for _, p := range m.params {
		if p.Key != key {
			continue
		}
		switch v := p.Value.(type) {
		case string:
			return v, true
		case Token:
			return string(v), true
		}
		return "", false
	}
	return "", false
}
