# Security

This project is pre-release. `v0.1.0-alpha.2` passed a live acceptance test of its core paths ([record](docs/acceptance.md)), but there has been no independent security review, and rate-limit boundary, fault-injection and long-running tests have not been done. The v0.2 features on the development branch have not been live-tested. Do not infer a security audit or production readiness.

## Reporting a vulnerability

Do not include credentials, private keys, or tokens in issues. Once private vulnerability reporting is enabled for the public repository, use [GitHub's private report form](https://github.com/sakajunquality/gsts/security/advisories/new). If that form is unavailable, contact the maintainer through an existing private channel; a public issue may request a private contact without disclosing exploit details.

## Trust boundaries

- The GitHub App key can authenticate as the App across all its installations. The gsts runtime's signing permission is consequently sensitive even though it cannot export key material. Restrict deployment, runtime IAM, and code changes.
- Repository default-branch writers can change repo policies. Org policy-repository writers can grant org-wide authority. Protect both with reviews, CODEOWNERS, and rulesets suitable for your organization.
- Permission ceilings come from the policy and GitHub App installation. Repository policies cannot grant organization-level permissions. Org permissions are not constrained by a `repositories` list.
- `[google] project` includes future matching service accounts. Email selectors can match a recreated account with the same email. Add numeric `subject` when immutable identity is needed.
- Audience overrides opt into accepting tokens issued for another audience. Avoid broad audience patterns. `azp` is not checked by default; pin it with `claim` or `claim_pattern` if needed.
- Service account impersonation permissions can allow another principal to mint a valid caller ID token. Control those permissions outside gsts.
- Replay prevention is per instance and in memory: each instance accepts a given ID token once (`GSTS_REPLAY_PROTECTION`, default on). There is no fleet-wide store, so a stolen token may still be accepted once by each other instance or after a restart, and a full store (`GSTS_REPLAY_MAX_ENTRIES`) refuses exchanges with 429 rather than evicting live entries. Tokens are keyed by their decoded bytes, so alternate base64url encodings of one signature count as the same token. A `max_token_lifetime` policy restricts accepted ID-token lifetime; it does not shorten GitHub's returned token lifetime.
- The service audience allowlist (`GSTS_ALLOWED_AUDIENCES`, default `GSTS_IDENTIFIER`) is enforced after signature and timestamp verification and before any KMS or GitHub call; policy audience overrides can only select among allowlisted audiences. A validly signed token from an allowed issuer for any allowlisted audience still triggers App signing, installation lookup and a policy read before the policy's own audience, subject and claim checks run. The App's GitHub rate limit is shared; use org allowlists and monitor denied exchanges.
- Per-instance admission limits bound exchange attempts, including invalid credentials, before OIDC, KMS or GitHub work: a token bucket (default 60/minute, burst 10) and an in-flight cap (default 16); excess requests get 429 `overloaded`. They are in memory and per instance, so they are not a fleet-wide quota or per-identity fairness, and new instances and restarts start with a full burst. See [admission controls](docs/api.md#admission-and-retry-controls).
- Temporary read tokens are revoked on normal success/failure paths, including request cancellation. An outage or process crash can leave them valid until expiry. Network uncertainty during token creation can also orphan a token. There is no exactly-once guarantee.
- HTTP responses do not reveal claim mismatch details. Logs contain authenticated identity information and need access controls, retention policy, and review.

## Key handling

GitHub generates the private key and downloads it as PEM. Initial import necessarily handles plaintext outside KMS. The import command performs wrapping in memory, but managed-language memory is not guaranteed to be securely erased. Choose a trusted import machine and account for backups and snapshots when deleting PEM copies. Never commit PEM, Terraform state, ADC files, or tokens.

Production configuration uses KMS only. `file` and `env` are explicitly gated by `GSTS_ALLOW_INSECURE_KEY=1` and are for local development. Do not set this flag in deployed services.

## Before a public release

The live acceptance runbook has been completed for `v0.1.0-alpha.2` ([record](docs/acceptance.md)); it did not cover rate-limit boundary load, KMS/GitHub fault injection or long-running operation, nor the v0.2 features. Before a public release: enable private vulnerability reporting, live-test the v0.2 features, run the remaining tests above, review dependencies and container provenance, verify package visibility, and arrange an independent security review of the authorization and cleanup paths. The CI workflow never requires production credentials.
