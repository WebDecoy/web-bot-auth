package webbotauth

import (
	"encoding/json"
	"os"
	"testing"
)

// Signature-Agent parsing vectors are copied verbatim from
// cloudflare/web-bot-auth (packages/web-bot-auth).
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
			if len(refs) != len(v.Entries) {
				t.Fatalf("got %d entries, want %d", len(refs), len(v.Entries))
			}
			for i, want := range v.Entries {
				got := refs[i]
				if got.Label != want.Label || got.URI != want.URI || string(got.Type) != want.Type {
					t.Errorf("entry %d = %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

func TestParseSignatureAgentLegacyString(t *testing.T) {
	refs, err := parseSignatureAgent([]string{`"https://signature-agent.test"`})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Label != "" || refs[0].URI != "https://signature-agent.test" || refs[0].Type != AgentRefDirectory {
		t.Errorf("unexpected refs: %+v", refs)
	}
}

func TestKeySetURL(t *testing.T) {
	cases := []struct {
		ref  AgentRef
		want string
		err  bool
	}{
		{AgentRef{URI: "https://agent.example", Type: AgentRefDirectory}, "https://agent.example/.well-known/http-message-signatures-directory", false},
		{AgentRef{URI: "https://agent.example/some/path", Type: AgentRefDirectory}, "https://agent.example/.well-known/http-message-signatures-directory", false},
		{AgentRef{URI: "https://agent.example/jwks.json", Type: AgentRefJWKSURI}, "https://agent.example/jwks.json", false},
		{AgentRef{URI: "http://agent.example", Type: AgentRefDirectory}, "", true},
		{AgentRef{URI: "https://agent.example/card", Type: AgentRefCIMD}, "", true},
	}
	for _, c := range cases {
		got, err := c.ref.keySetURL()
		if c.err {
			if err == nil {
				t.Errorf("keySetURL(%+v): expected error, got %q", c.ref, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("keySetURL(%+v): %v", c.ref, err)
			continue
		}
		if got != c.want {
			t.Errorf("keySetURL(%+v) = %q, want %q", c.ref, got, c.want)
		}
	}
}
