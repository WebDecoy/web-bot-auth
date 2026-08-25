package webbotauth

import "testing"

// TestDirectoryContentTypeGate covers draft-02 §5.5.1, which requires the
// well-known directory to be served as
// application/http-message-signatures-directory+json.
//
// The gate is deliberately lenient about WHICH json type, because the MUST
// binds the server and refusing application/jwk-set+json would fail against
// directories published before the media type was registered. What it exists to
// stop is parsing something that was never a directory at all.
func TestDirectoryContentTypeGate(t *testing.T) {
	accepted := []string{
		"application/http-message-signatures-directory+json",
		"application/http-message-signatures-directory+json; charset=utf-8",
		"application/jwk-set+json",
		"application/json",
		"APPLICATION/JSON",
		"", // absent: a server omission, not a wrong answer
	}
	for _, ct := range accepted {
		if err := checkDirectoryContentType(ct); err != nil {
			t.Errorf("checkDirectoryContentType(%q) = %v, want accepted", ct, err)
		}
	}

	// These are the responses that used to be parsed as key sets. A verifier
	// that reads them and then reports "no key matching keyid" is describing
	// the operator's directory when the truth is we never reached one.
	rejected := []string{
		"text/html",
		"text/html; charset=utf-8",
		"text/plain",
		"application/xml",
		"application/octet-stream",
	}
	for _, ct := range rejected {
		if err := checkDirectoryContentType(ct); err == nil {
			t.Errorf("checkDirectoryContentType(%q) = nil, want rejected", ct)
		}
	}
}
