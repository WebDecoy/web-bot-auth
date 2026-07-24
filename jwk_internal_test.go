package webbotauth

import "testing"

func TestNormalizeEpoch(t *testing.T) {
	cases := map[int64]int64{
		0:              0,
		1743465600:     1743465600,  // seconds pass through
		1743465600000:  1743465600,  // milliseconds scale down
		32503680000:    32503680000, // year 3000 in seconds still passes through
		32503680000000: 32503680000, // year 3000 in ms scales
	}
	for in, want := range cases {
		if got := normalizeEpoch(in); got != want {
			t.Errorf("normalizeEpoch(%d) = %d, want %d", in, got, want)
		}
	}
}

// A key published with millisecond nbf (as Cloudflare Research's live
// directory does) must resolve as currently valid, not not-yet-valid.
func TestResolveNormalizesMillisecondNbf(t *testing.T) {
	set := KeySet{Keys: []JWK{{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
		Nbf: 1743465600000, // 2025-04-01 in milliseconds
	}}}
	keys := set.resolve()
	if len(keys) != 1 {
		t.Fatalf("resolved %d keys, want 1", len(keys))
	}
	if keys[0].nbf != 1743465600 {
		t.Errorf("nbf = %d, want 1743465600", keys[0].nbf)
	}
}
