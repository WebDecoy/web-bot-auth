package httpsig

import (
	"bytes"
	"testing"
)

func TestParseDictionaryRawCapture(t *testing.T) {
	input := `sig1=("@authority" "signature-agent");created=1;tag="web-bot-auth", sig2=("@target-uri");created=2`
	dict, err := parseDictionary(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(dict) != 2 {
		t.Fatalf("got %d members, want 2", len(dict))
	}
	if want := `("@authority" "signature-agent");created=1;tag="web-bot-auth"`; dict[0].Raw != want {
		t.Errorf("raw[0] = %q, want %q", dict[0].Raw, want)
	}
	if want := `("@target-uri");created=2`; dict[1].Raw != want {
		t.Errorf("raw[1] = %q, want %q", dict[1].Raw, want)
	}
	if dict[0].List == nil || len(dict[0].List.Items) != 2 {
		t.Fatalf("member 0 not parsed as 2-item inner list: %+v", dict[0])
	}
}

func TestParseDictionaryItemTypes(t *testing.T) {
	dict, err := parseDictionary(`a="str", b=:aGVsbG8=:, c=?1, d=42, e=token, f=-1.25, g`)
	if err != nil {
		t.Fatal(err)
	}
	if v := dict[0].Item.Value.(string); v != "str" {
		t.Errorf("string = %q", v)
	}
	if v := dict[1].Item.Value.([]byte); !bytes.Equal(v, []byte("hello")) {
		t.Errorf("bytes = %q", v)
	}
	if v := dict[2].Item.Value.(bool); v != true {
		t.Errorf("bool = %v", v)
	}
	if v := dict[3].Item.Value.(int64); v != 42 {
		t.Errorf("int = %d", v)
	}
	if v := dict[4].Item.Value.(Token); v != "token" {
		t.Errorf("token = %q", v)
	}
	if v := dict[5].Item.Value.(float64); v != -1.25 {
		t.Errorf("decimal = %v", v)
	}
	if v := dict[6].Item.Value.(bool); v != true {
		t.Errorf("valueless member = %v, want true", v)
	}
}

func TestParseDictionaryErrors(t *testing.T) {
	bad := []string{
		`=nope`,           // missing key
		`a=`,              // missing value
		`a="unterminated`, // unterminated string
		`a=:!!!:`,         // invalid base64
		`a=?2`,            // invalid boolean
		`a="x", `,         // trailing comma
		`a="x" b="y"`,     // missing comma
		`Upper=1`,         // uppercase key
		`a="bad\n"`,       // control char via literal is fine; escape check below
		`a="bad\x"`,       // invalid escape
	}
	for _, s := range bad {
		if _, err := parseDictionary(s); err == nil {
			t.Errorf("parseDictionary(%q): expected error", s)
		}
	}
}

func TestStringEscapes(t *testing.T) {
	dict, err := parseDictionary(`a="quote \" backslash \\"`)
	if err != nil {
		t.Fatal(err)
	}
	if v := dict[0].Item.Value.(string); v != `quote " backslash \` {
		t.Errorf("unescaped = %q", v)
	}
	out, err := dict[0].serializeValue()
	if err != nil {
		t.Fatal(err)
	}
	if out != `"quote \" backslash \\"` {
		t.Errorf("reserialized = %q", out)
	}
}

func TestSerializeRoundTrip(t *testing.T) {
	inputs := []string{
		`("@authority" "signature-agent";key="agent2");created=1735689600;keyid="abc";tag="web-bot-auth"`,
		`"https://signature-agent.test"`,
		`:aGVsbG8=:`,
		`(?1 42 token "s");p1;p2="x"`,
	}
	for _, in := range inputs {
		dict, err := parseDictionary("k=" + in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		out, err := dict[0].serializeValue()
		if err != nil {
			t.Fatalf("serialize %q: %v", in, err)
		}
		if out != in {
			t.Errorf("round trip: got %q, want %q", out, in)
		}
	}
}

func TestCanonicalFieldValue(t *testing.T) {
	got := canonicalFieldValue([]string{"  a   b\tc ", "d"})
	if want := "a b c, d"; got != want {
		t.Errorf("canonicalFieldValue = %q, want %q", got, want)
	}
}

func TestDerivedComponents(t *testing.T) {
	req := &Request{
		Method:    "get",
		Scheme:    "HTTPS",
		Authority: "Example.COM:443",
		Path:      "/a/b",
		Query:     "?x=1",
	}
	cases := map[string]string{
		"@method":         "GET",
		"@authority":      "example.com",
		"@scheme":         "https",
		"@target-uri":     "https://example.com/a/b?x=1",
		"@path":           "/a/b",
		"@query":          "?x=1",
		"@request-target": "/a/b?x=1",
	}
	for name, want := range cases {
		got, err := derivedComponent(req, name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if _, err := derivedComponent(req, "@status"); err == nil {
		t.Error("@status should be unsupported")
	}
	req.Query = ""
	if got, _ := derivedComponent(req, "@query"); got != "?" {
		t.Errorf("empty @query = %q, want \"?\"", got)
	}
	// Non-default port is preserved.
	req.Authority = "example.com:8443"
	if got, _ := derivedComponent(req, "@authority"); got != "example.com:8443" {
		t.Errorf("non-default port authority = %q", got)
	}
}
