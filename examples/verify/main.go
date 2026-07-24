// Command verify runs a demo server that classifies every request as
// verified / invalid / no-signature Web Bot Auth traffic.
package main

import (
	"encoding/json"
	"log"
	"net/http"

	webbotauth "github.com/WebDecoy/web-bot-auth"
)

func main() {
	verifier := webbotauth.NewVerifier(
		// Demo posture: fetch any https directory a request names, behind
		// the built-in non-global-address guard. Production verifiers
		// should prefer WithDirectoryAllowlist.
		webbotauth.WithOpenDirectories(),
	)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		res := verifier.Verify(r.Context(), webbotauth.RequestFromHTTP(r, webbotauth.WithScheme("https")))
		out := map[string]any{"status": res.Status.String()}
		if res.Status == webbotauth.StatusVerified {
			out["agent"] = res.Agent
			out["keyid"] = res.KeyID
			out["algorithm"] = res.Algorithm
		}
		if len(res.Errors) > 0 {
			msgs := make([]string, len(res.Errors))
			for i, e := range res.Errors {
				msgs[i] = e.Error()
			}
			out["errors"] = msgs
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})

	log.Println("listening on :8080 — send signed requests (see examples/sign)")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
