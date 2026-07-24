package httpsig

import "testing"

// The parsers face attacker-controlled header bytes; fuzzing asserts they
// never panic and that anything they accept re-serializes without error.
func FuzzParseDictionary(f *testing.F) {
	seeds := []string{
		`sig1=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="k";alg="ed25519";expires=1735693200;nonce="n";tag="web-bot-auth"`,
		`sig1=:aGVsbG8=:, sig2=:d29ybGQ=:`,
		`sig1="https://signature-agent.test";type=jwks_uri`,
		`a`, `a=?1`, `a=-9.999`, `a=(((`, `a="\\\"`, `a=:=:`, `*x-0.a=t;;`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		dict, err := parseDictionary(s)
		if err != nil {
			return
		}
		for i := range dict {
			// Accepted input must be serializable (round-trip safety).
			if _, err := dict[i].serializeValue(); err != nil && dict[i].Raw != "" {
				t.Errorf("accepted member %q does not re-serialize: %v", dict[i].Raw, err)
			}
		}
	})
}

func FuzzParseSignatureInput(f *testing.F) {
	f.Add(`sig1=("@authority");created=1;expires=2;keyid="k";tag="web-bot-auth"`)
	f.Add(`sig1=nope`)
	f.Fuzz(func(t *testing.T, s string) {
		members, err := ParseSignatureInput([]string{s})
		if err != nil {
			return
		}
		for i := range members {
			m := &members[i]
			// Accessors must not panic on arbitrary accepted input.
			m.Created()
			m.Expires()
			m.KeyID()
			m.Tag()
			m.Nonce()
			m.Alg()
			m.CoversComponent("@authority")
		}
	})
}
