# Changelog

## Unreleased

- Add per-instance, in-memory ID-token replay prevention (`GSTS_REPLAY_PROTECTION`, `GSTS_REPLAY_MAX_ENTRIES`); reused tokens get 403 `token_replayed`.
- Add opt-in organization trusted-issuer allowlist (`GSTS_ORG_TRUST_FILE`, `gsts policy validate-trust`); issuers outside the org file get 403 `issuer_not_trusted`.
- Add exact-match `claim` table to trust policies (strings, integers, booleans; strict types) for pinning immutable claims such as `repository_id`.
- Document the `v0.1.0-alpha.2` live acceptance record (`docs/acceptance.md`) and the sts-cat migration guide (`docs/migration-sts-cat.md`); update status wording and reconcile SECURITY.md trust-boundary text with the current admission controls.
- The v0.2 features above have not been live-tested.

## v0.1.0-alpha.2

- Separate process liveness (`/live`) from fresh App signing/authentication readiness (`/ready`); remove `/healthz`.
- Reject unlisted audiences before KMS/GitHub and bound per-instance exchange concurrency/rate/burst.
- Add a reusable Node24 GitHub Action with OIDC, masking and post-job token revocation.
- Add offline `policy validate/test` commands and workflow-reference fixtures.
- Propagate rate-limit retry delays and log request IDs, stage timings and policy content fingerprints.
- Passed live Cloud Run / Cloud KMS / GitHub acceptance of the core exchange, policy and revocation paths; see `docs/acceptance.md` for what was and was not covered.

## v0.1.0-alpha.1

- Update Go to 1.26.9 and x/net to v0.60.0 with required transitive dependencies for the October security fixes.
- Add prerelease/manual GHCR publication, digest-based promotion, and dual-platform version checks.
- OIDC exchange for Google service accounts and GitHub Actions.
- Repository/org TOML trust policies, Google selectors, and request scope narrowing.
- Cloud KMS signing with CRC32C integrity checks and App JWT caching.
- In-memory RSA/AES KMS import command and local-only PEM signer.
- Default-branch policy reads, scoped temporary tokens, and explicit revocation.
- Cloud Run/KMS/IAM Terraform module, nonroot container, and deployment runbook.
- Structured audit logs, security tests, CI, and opt-in tag-triggered image publication.
