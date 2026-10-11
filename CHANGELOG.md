# Changelog

## Unreleased

- Separate process liveness (`/live`) from fresh App signing/authentication readiness (`/ready`); remove `/healthz`.
- Add per-instance, in-memory ID-token replay prevention (`GSTS_REPLAY_PROTECTION`, `GSTS_REPLAY_MAX_ENTRIES`); reused tokens get 403 `token_replayed`.
- Reject unlisted audiences before KMS/GitHub and bound per-instance exchange concurrency/rate/burst.
- Add a reusable Node24 GitHub Action with OIDC, masking and post-job token revocation.
- Add offline `policy validate/test` commands and workflow-reference fixtures.
- Propagate rate-limit retry delays and log request IDs, stage timings and policy content fingerprints.

- Update Go to 1.26.9 and x/net to v0.60.0 with required transitive dependencies for the October security fixes.
- Add prerelease/manual GHCR publication, digest-based promotion, and dual-platform version checks.

- OIDC exchange for Google service accounts and GitHub Actions.
- Repository/org TOML trust policies, Google selectors, and request scope narrowing.
- Cloud KMS signing with CRC32C integrity checks and App JWT caching.
- In-memory RSA/AES KMS import command and local-only PEM signer.
- Default-branch policy reads, scoped temporary tokens, and explicit revocation.
- Cloud Run/KMS/IAM Terraform module, nonroot container, and deployment runbook.
- Structured audit logs, security tests, CI, and opt-in tag-triggered image publication.

Release is pending live Cloud Run / KMS / GitHub acceptance.
