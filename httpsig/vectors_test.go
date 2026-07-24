package httpsig_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/WebDecoy/web-bot-auth/httpsig"
)

// Architecture vectors are copied verbatim from cloudflare/web-bot-auth.
// They are the differential-correctness anchor: the signatures were produced
// by the reference implementation, so verifying them proves our signature
// base matches theirs byte for byte.

type vector struct {
	Key struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"key"`
	TargetURL         string `json:"target_url"`
	Label             string `json:"label"`
	Signature         string `json:"signature"`
	SignatureInput    string `json:"signature_input"`
	SignatureAgent    string `json:"signature_agent"`
	SignatureAgentKey string `json:"signature_agent_key"`
}

func loadVectors(t *testing.T, name string) []vector {
	t.Helper()
	data, err := os.ReadFile("../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors loaded")
	}
	return vs
}

func vectorPublicKey(t *testing.T, v *vector) (crypto.PublicKey, httpsig.Algorithm) {
	t.Helper()
	switch v.Key.Kty {
	case "OKP":
		raw, err := base64.RawURLEncoding.DecodeString(v.Key.X)
		if err != nil {
			t.Fatal(err)
		}
		return ed25519.PublicKey(raw), httpsig.AlgEd25519
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(v.Key.N)
		if err != nil {
			t.Fatal(err)
		}
		e, err := base64.RawURLEncoding.DecodeString(v.Key.E)
		if err != nil {
			t.Fatal(err)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, httpsig.AlgRSAPSSSHA512
	default:
		t.Fatalf("unsupported vector kty %q", v.Key.Kty)
		return nil, ""
	}
}

func vectorRequest(t *testing.T, v *vector) *httpsig.Request {
	t.Helper()
	u, err := url.Parse(v.TargetURL)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("Signature", v.Signature)
	h.Set("Signature-Input", v.SignatureInput)
	if v.SignatureAgent != "" {
		h.Set("Signature-Agent", v.SignatureAgent)
	}
	query := ""
	if u.RawQuery != "" {
		query = "?" + u.RawQuery
	}
	return &httpsig.Request{
		Method:    "GET",
		Scheme:    u.Scheme,
		Authority: u.Host,
		Path:      u.EscapedPath(),
		Query:     query,
		Header:    h,
	}
}

func TestReferenceVectors(t *testing.T) {
	for _, file := range []string{"web_bot_auth_architecture_v1.json", "web_bot_auth_architecture_v2.json"} {
		t.Run(file, func(t *testing.T) {
			for i, v := range loadVectors(t, file) {
				v := v
				t.Run(v.Label, func(t *testing.T) {
					req := vectorRequest(t, &v)

					members, err := httpsig.ParseSignatureInput(req.Header.Values("Signature-Input"))
					if err != nil {
						t.Fatal(err)
					}
					var member *httpsig.SignatureMember
					for j := range members {
						if members[j].Label == v.Label {
							member = &members[j]
						}
					}
					if member == nil {
						t.Fatalf("label %q not found in parsed Signature-Input", v.Label)
					}
					if tag, ok := member.Tag(); !ok || tag != "web-bot-auth" {
						t.Fatalf("tag = %q, want web-bot-auth", tag)
					}

					sigs, err := httpsig.ParseSignature(req.Header.Values("Signature"))
					if err != nil {
						t.Fatal(err)
					}
					sig, ok := sigs[v.Label]
					if !ok {
						t.Fatalf("label %q not found in parsed Signature", v.Label)
					}

					base, err := httpsig.SignatureBase(req, member)
					if err != nil {
						t.Fatal(err)
					}

					pub, alg := vectorPublicKey(t, &v)
					if err := httpsig.VerifySignature(pub, alg, base, sig); err != nil {
						t.Fatalf("vector %d: %v\nbase:\n%s", i, err, base)
					}

					// Tampering with the base must break verification.
					tampered := append([]byte(nil), base...)
					tampered[0] ^= 0x01
					if err := httpsig.VerifySignature(pub, alg, tampered, sig); err == nil {
						t.Fatal("tampered base still verified")
					}

					// Truncated signatures must not verify.
					if err := httpsig.VerifySignature(pub, alg, base, sig[:len(sig)-1]); err == nil {
						t.Fatal("truncated signature still verified")
					}
				})
			}
		})
	}
}

// The signature base must reproduce the raw Signature-Input member text
// verbatim in the @signature-params line.
func TestSignatureBaseUsesRawInput(t *testing.T) {
	vs := loadVectors(t, "web_bot_auth_architecture_v1.json")
	v := vs[0]
	req := vectorRequest(t, &v)
	members, err := httpsig.ParseSignatureInput(req.Header.Values("Signature-Input"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := httpsig.SignatureBase(req, &members[0])
	if err != nil {
		t.Fatal(err)
	}
	rawMember := strings.TrimPrefix(v.SignatureInput, v.Label+"=")
	want := `"@signature-params": ` + rawMember
	if !strings.HasSuffix(string(base), want) {
		t.Errorf("base does not end with raw @signature-params line\nbase:\n%s\nwant suffix:\n%s", base, want)
	}
	if !strings.HasPrefix(string(base), `"@authority": example.com`+"\n") {
		t.Errorf("base does not start with @authority line:\n%s", base)
	}
}
