package thumbprint

import (
	"encoding/json"
	"os"
	"testing"
)

// Fixture vectors are copied from cloudflare/web-bot-auth
// (packages/jsonwebkey-thumbprint); the RSA one is RFC 7638's own example.
func TestFromJWKVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name       string `json:"name"`
		JWK        string `json:"jwk"`
		Thumbprint string `json:"thumbprint"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, err := FromJWK([]byte(v.JWK))
			if err != nil {
				t.Fatal(err)
			}
			if got != v.Thumbprint {
				t.Errorf("thumbprint = %q, want %q", got, v.Thumbprint)
			}
		})
	}
}

// Web Bot Auth architecture test vectors pin these keyids for the shared
// test keys; they double as known-answer tests for RSA and OKP.
func TestWebBotAuthTestKeys(t *testing.T) {
	rsaN := "r4tmm3r20Wd_PbqvP1s2-QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct-Lh1GH45x28Rw3Ry53mm-oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL-Wokqltd11nqqzi-bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4aOT9v6d-nb4bnNkQVklLQ3fVAvJm-xdDOp9LCNCN48V2pnDOkFV6-U9nV5oyc6XI2w"
	if got, want := RSA(rsaN, "AQAB"), "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA"; got != want {
		t.Errorf("RSA thumbprint = %q, want %q", got, want)
	}
	if got, want := OKP("Ed25519", "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"), "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"; got != want {
		t.Errorf("OKP thumbprint = %q, want %q", got, want)
	}
}

func TestFromJWKUnsupported(t *testing.T) {
	if _, err := FromJWK([]byte(`{"kty":"EC","crv":"P-256","x":"a","y":"b"}`)); err == nil {
		t.Error("expected error for EC key")
	}
	if _, err := FromJWK([]byte(`not json`)); err == nil {
		t.Error("expected error for invalid JSON")
	}
}
