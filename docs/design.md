# Implementation decisions

The initial September 2026 proposal is implemented as an independent Go service with these concrete choices:

- One App, one Cloud Run service, one import-only RSA-2048 KMS signing key. No Firestore, Secret Manager, webhook, or eventing dependency at runtime.
- Google and GitHub Actions issuers only. Discovery issuer must match exactly. Google JWKS hosts are `www.googleapis.com` / `accounts.google.com`; Actions uses its issuer host. HTTPS only, no redirects, fixed outbound destinations, bounded response sizes. Discovery URI is retained per process; JWKS uses response max-age (minus Age), or five minutes without a cache directive. Unknown-key refreshes are limited to one per 30 seconds per issuer.
- RS256, required `iss` / `sub` / `aud` / numeric `iat` / numeric `exp`, and optional `nbf`. Timestamps must be integer Unix seconds in years 1970–9999; this prevents numeric overflow in date conversion. No timestamp leeway; keep clocks synchronized. Identity/signature/time validation precedes GitHub access. A service audience allowlist is checked before signing/GitHub access. After policy loading, the policy must match an audience in the admitted intersection. No caller token is issued before both stages succeed.
- GitHub installation IDs are cached for ten minutes, at most 1,000 orgs per process. Policies and returned tokens are never cached. A stale installation ID can cause failures until cache expiry after uninstall/reinstall.
- App JWT `iat` is backdated by 60 seconds and `exp` is nine minutes ahead (ten minutes from `iat`). Cache refresh is after eight minutes, leaving one minute before expiry. This resolves the proposal's conflicting “one KMS call per exchange” / “nine-minute cache” statements. Concurrent callers share a single signing operation.
- Read tokens have `contents:read` on exactly the policy repository (plus the org policy repository when `GSTS_ORG_TRUST_FILE` is set) and are revoked immediately after fetching the policy, before caller-token issuance. Cleanup uses an independent ten-second context even when the caller disconnects. Revocation failures fail the exchange. Remote outages/process termination can still prevent revocation; those tokens expire according to GitHub's lifetime.
- Request narrowing ships immediately. Empty permissions/repository constraints are rejected instead of turning into GitHub's default full installation scope. Org permissions require org policies; repository policies cannot widen authority to the organization.
- KMS import uses Google's Go SDK, RSA-OAEP-SHA256 to wrap an ephemeral AES-256 key, and Tink RFC 5649 KWP to wrap the PKCS#8 material. No custom AES or RSA implementation. KMS signing includes CRC32C request/response integrity checks.
- Startup App-permission introspection is best effort, not readiness. It supplies warning logs when available; GitHub's issuance API is authoritative.
- The initial Cloud Run revision must listen before the signing key is imported. Terraform uses `/live` for startup, while `/ready` performs a fresh signing and GitHub authentication check (10-second result cache). Correct first-version imports need no second apply; rotations do.
- `image` is required until a release actually exists. `identifier` is a stable audience URL independent of the generated service URL. Custom-domain/DNS resources are outside the minimal Terraform module. Private package deployment can require separate image storage setup.

## Compatibility

The `POST /token` request shape and base TOML names follow [sts-cat](https://github.com/sorah/sts-cat). Responses add `expires_at` and `permissions`. The default path differs: set `GSTS_POLICY_PATH_PREFIX=.github/sts-cat` to read policies at the existing location. This is compatible vocabulary and request shape, **not a guarantee of byte-for-byte or semantic parity**:

- Regexes use Go RE2 rather than Rust regex syntax.
- Lifetime limits use required `iat` (`exp - iat`), not `nbf` fallback.
- Unknown policy keys are rejected.
- Built-in issuer support is intentionally limited.
- Empty repository lists and empty permission maps are denied.
- Repository policies cannot grant organization permissions.
- Google email-only shorthand does not pin an immutable numeric subject unless the policy also specifies one.

No source code from sts-cat or octo-sts was copied. Their designs are acknowledged in the README.

## Known limits / release gate

Per-instance concurrency and request-rate limits bound exchange attempts before OIDC work. These do not provide per-tenant fairness or a distributed quota.

No exchange-result idempotency, multi-App routing, GHES validation, custom issuer registration. Replay prevention is per instance only: each instance remembers the SHA-256 of consumed ID tokens in memory until their `exp` (bounded by `GSTS_REPLAY_MAX_ENTRIES`, evicting the soonest-expiring entry when full), so the same token may still be accepted once by each Cloud Run instance, and again after a restart; there is no fleet-wide store. Clients must mint a fresh ID token for every attempt. Policy audience overrides should be reviewed as security-sensitive changes. GitHub rate limits depend on installation/plan and endpoint; a fixed 15,000 requests/hour must not be assumed. Each exchange normally uses four GitHub calls (read-token creation, policy fetch, revocation, caller-token creation), or five when `GSTS_ORG_TRUST_FILE` is set (one more file read for the org trust file), plus installation lookup on a cache miss and best-effort App introspection at startup.

Live Cloud Run acceptance, KMS import/sign permissions, GitHub App behavior, and GHCR publication/visibility must be verified before announcing v0.1. Name availability/trademark checks and an independent security review remain publication tasks; the working repository name does not establish uniqueness or Google affiliation.
