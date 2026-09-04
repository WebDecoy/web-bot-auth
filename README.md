# web-bot-auth (Go)

**Verify and produce [Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/documents/) signatures in Go — cryptographic identity for bots and AI agents, with zero dependencies.**

[![CI](https://github.com/WebDecoy/web-bot-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/WebDecoy/web-bot-auth/actions/workflows/ci.yml)

Web Bot Auth replaces spoofable user-agent strings with cryptographic proof: agents sign each request with [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421) (tag `web-bot-auth`), publish their public keys in an HTTP Message Signatures directory, and identify the directory via the `Signature-Agent` header. OpenAI signs Operator requests today; Cloudflare, Vercel, and AWS WAF verify at their edges. This module lets any Go service do the same.

Built and maintained by [WebDecoy](https://webdecoy.com). Ported from and cross-validated against [`cloudflare/web-bot-auth`](https://github.com/cloudflare/web-bot-auth) — the reference implementation's test vectors run in this repo's CI.

- **Zero dependencies** — `crypto/ed25519`, `crypto/rsa`, and the standard library only.
- **Both draft generations** — the current `Signature-Agent` dictionary form with `key="..."` member extraction, and the earlier bare-string form deployed signers still send.
- **Verification is a verdict, not an error** — `no-signature` / `verified` / `invalid`, designed for detection pipelines where an *invalid* claim of agent identity is the most interesting outcome.
- **SSRF-guarded key discovery** — https-only, host allowlist (or explicit open mode with a non-global-address dialer), size caps, per-hop redirect re-validation, TTL + stale-while-revalidate caching.

## Install

```
go get github.com/WebDecoy/web-bot-auth
```

## Verify inbound requests

```go
import (
    "net/http"

    webbotauth "github.com/WebDecoy/web-bot-auth"
)

verifier := webbotauth.NewVerifier(
    // Fetch keys only from directories you trust:
    webbotauth.WithDirectoryAllowlist("operator.openai.com", ".webdecoy.com"),
    // ...or verify anything that signs (guarded dialer): webbotauth.WithOpenDirectories(),
)

func handler(w http.ResponseWriter, r *http.Request) {
    res := verifier.Verify(r.Context(), webbotauth.RequestFromHTTP(r))
    switch res.Status {
    case webbotauth.StatusVerified:
        // res.Agent, res.KeyID, res.Algorithm identify the signer.
    case webbotauth.StatusInvalid:
        // The request *claimed* a signed identity and failed to prove it.
        // res.Errors says why. Treat as a detection signal.
    case webbotauth.StatusNoSignature:
        // Plain traffic.
    }
}
```

Behind a TLS-terminating proxy pass the original scheme: `webbotauth.RequestFromHTTP(r, webbotauth.WithScheme("https"))`.

## Sign outbound requests (operate a bot)

```go
signer, _ := webbotauth.NewSigner(ed25519Key,
    webbotauth.WithSignatureAgent("https://mybot.example"), // origin serving your key directory
)
req, _ := http.NewRequest("GET", "https://example.com/page", nil)
_ = signer.SignRequest(req) // sets Signature, Signature-Input, Signature-Agent
```

Publish `signer.PublicJWK()` in a JWK Set at `https://mybot.example/.well-known/http-message-signatures-directory`.

The signer emits the WG draft's dictionary form by default and binds the exact
member with `"signature-agent";key="sig1"`. For a deployed verifier that still
requires the earlier bare-string form, add `webbotauth.WithLegacySignatureAgent()`.

## Packages

| Package | Contents |
|---|---|
| `webbotauth` (root) | `Verifier`, `Signer`, `JWK`/`KeySet`, `Signature-Agent` parsing, directory client |
| `httpsig` | The RFC 9421 profile Web Bot Auth uses: signature base construction, header parsing, Ed25519 + RSASSA-PSS-SHA512 |
| `thumbprint` | RFC 7638 / RFC 8037 JWK thumbprints (Web Bot Auth's `keyid`) |

## Spec status

Implements `draft-ietf-webbotauth-httpsig-protocol-00` (September 2026), the
working-group adoption of `draft-meunier-webbotauth-httpsig-protocol-02`, plus
the earlier bare-string `Signature-Agent` form for compatibility with deployed
verifiers. Releases are tagged against draft revisions and this README states
the pinned revision.

### Profile boundary (deliberate non-goals)

This is a Web Bot Auth implementation, not a general RFC 9421 library: no response signing, no request-response binding, no `Accept-Signature` negotiation, no HMAC/ECDSA, derived components limited to the request set. If a future draft needs more, the profile grows with it — the point is that what's here is exactly what the protocol exercises, tested against the reference vectors.

## Security model

- Directory URLs come from the *request under verification* — they are attacker-controlled input. The default fetch client is https-only, refuses loopback/private/link-local addresses in open mode, caps responses at 1 MiB, and re-checks policy on every redirect hop. Supplying your own `http.Client` transfers that responsibility to you.
- Verification failures never panic and never error out of `Verify`; malformed input from the network is a classification, not an exception. Both parsers are fuzzed in CI.
- Replay defense is delegated: signatures carry nonces, and `WithNonceChecker` hands enforcement to your store (memory, Redis, ...). The default accepts any nonce within the signature's validity window, per the draft's baseline.

## License

Apache 2.0. Portions ported from [`cloudflare/web-bot-auth`](https://github.com/cloudflare/web-bot-auth) (Apache 2.0) — see `NOTICE`. Test vectors copied verbatim from that repository.
