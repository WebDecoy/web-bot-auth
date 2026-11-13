package webbotauth

import (
	"encoding/json"
	"os"
	"testing"
)

// The parsing vectors are copied verbatim from cloudflare/web-bot-auth
// (packages/web-bot-auth). They were written for draft 00, where a type
// parameter chose the resolution mechanism. Draft 01 §5.2.1 says a member
// with parameters MUST be ignored, so only the untyped member survives.
func TestParseSignatureAgentVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/web_bot_auth_signature_agent_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name    string `json:"name"`
		Header  string `json:"header"`
		Entries []struct {
			Label string `json:"label"`
			URI   string `json:"uri"`
			Type  string `json:"type"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			refs, err := parseSignatureAgent([]string{v.Header})
			if err != nil {
				t.Fatal(err)
			}
			var want []AgentRef
			for _, e := range v.Entries {
				if e.Type == "directory" { // the draft-00 default: no parameter on the wire
					want = append(want, AgentRef{Label: e.Label, URI: e.URI})
				}
			}
			if len(refs) != len(want) {
				t.Fatalf("got %+v, want %+v", refs, want)
			}
			for i := range want {
				if refs[i] != want[i] {
					t.Errorf("entry %d = %+v, want %+v", i, refs[i], want[i])
				}
			}
		})
	}
}

func TestParseSignatureAgentIgnoresParameterizedMembers(t *testing.T) {
	refs, err := parseSignatureAgent([]string{`a="https://a.example/keys";type=jwks_uri, b="https://b.example", c="https://c.example";x=1`})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0] != (AgentRef{Label: "b", URI: "https://b.example"}) {
		t.Errorf("refs = %+v, want only member b", refs)
	}
}

func TestParseSignatureAgentLegacyString(t *testing.T) {
	refs, err := parseSignatureAgent([]string{`"https://signature-agent.test"`})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0] != (AgentRef{URI: "https://signature-agent.test"}) {
		t.Errorf("unexpected refs: %+v", refs)
	}
}

func TestKeySetURL(t *testing.T) {
	const wk = "https://agent.example/.well-known/http-message-signatures-directory"
	cases := []struct {
		uri  string
		want string
		err  bool
	}{
		// Legacy origin form: the well-known directory.
		{"https://agent.example", wk, false},
		{"https://agent.example/", wk, false},
		// Draft 01: everything else is fetched as sent.
		{"https://agent.example/.well-known/http-message-signatures-directory", wk, false},
		{"https://agent.example/jwks.json", "https://agent.example/jwks.json", false},
		{"https://agent.example/some/path", "https://agent.example/some/path", false},
		{"https://agent.example/keys?v=2", "https://agent.example/keys?v=2", false},
		{"https://agent.example/?v=2", "https://agent.example/?v=2", false},
		{"https://agent.example/keys#frag", "https://agent.example/keys", false},
		{"HTTPS://agent.example/keys", "https://agent.example/keys", false},
		{"http://agent.example", "", true},
		{"https:///keys", "", true},
		{"https://user:pw@agent.example/keys", "", true},
		{"agent.example", "", true},
	}
	for _, c := range cases {
		got, err := AgentRef{URI: c.uri}.keySetURL()
		if c.err {
			if err == nil {
				t.Errorf("keySetURL(%q): expected error, got %q", c.uri, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("keySetURL(%q): %v", c.uri, err)
			continue
		}
		if got != c.want {
			t.Errorf("keySetURL(%q) = %q, want %q", c.uri, got, c.want)
		}
	}
}

func TestAgentIdentifier(t *testing.T) {
	cases := map[string]string{
		"https://agent.example/keys":                "https://agent.example/keys",
		"https://agent.example/keys?v=1":            "https://agent.example/keys",
		"https://agent.example/keys?v=2":            "https://agent.example/keys",
		"HTTPS://Agent.Example:443/keys":            "https://agent.example/keys",
		"https://agent.example:8443/keys":           "https://agent.example:8443/keys",
		"https://agent.example":                     "https://agent.example/",
		"https://agent.example/a/../keys":           "https://agent.example/keys",
		"https://agent.example/./keys":              "https://agent.example/keys",
		"https://agent.example/k%c3%a9ys":           "https://agent.example/k%C3%A9ys",
		"https://agent.example/keys#x":              "https://agent.example/keys",
		"https://agent.example/keys/":               "https://agent.example/keys/",
		"https://agent.example/.well-known/x?cache": "https://agent.example/.well-known/x",
	}
	for in, want := range cases {
		got, err := AgentIdentifier(in)
		if err != nil {
			t.Errorf("AgentIdentifier(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("AgentIdentifier(%q) = %q, want %q", in, got, want)
		}
	}
}

// The resolution vectors are shared with the TypeScript ports, so this test
// is what keeps them honest.
func TestResolveSignatureAgentVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/signature_agent_resolution.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Valid []struct {
			Value, Fetch, Identifier string
		} `json:"valid"`
		Invalid []string `json:"invalid"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Valid {
		fetch, id, err := ResolveSignatureAgent(c.Value)
		if err != nil {
			t.Errorf("%q: %v", c.Value, err)
			continue
		}
		if fetch != c.Fetch || id != c.Identifier {
			t.Errorf("%q = (%q, %q), want (%q, %q)", c.Value, fetch, id, c.Fetch, c.Identifier)
		}
	}
	for _, in := range v.Invalid {
		if _, _, err := ResolveSignatureAgent(in); err == nil {
			t.Errorf("%q: expected an error", in)
		}
	}
}
