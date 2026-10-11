# Acceptance and release-gate records

## v0.2.0 release gate

This section records the release-gate work for `v0.2.0`, done on 2026-10-11 against `v0.2.0-alpha.1` and the fixes on the `release/v0.2.0` branch. Each item states what was done and what it does not show.

### Repository and package

- Private vulnerability reporting, secret scanning with push protection, Dependabot alerts and Dependabot security updates are enabled on the repository.
- `govulncheck ./...`: zero vulnerabilities affect the code. One advisory (GO-2026-5932, `golang.org/x/crypto/openpgp`) is present in a required module, is not called by gsts, and has no fixed version.
- `ghcr.io/sakajunquality/gsts:v0.2.0-alpha.1` is pullable anonymously (manifest request returned HTTP 200 with an anonymous registry token). The registry holds provenance (`mode=max`) and SBOM attestations for `linux/amd64` and `linux/arm64`.
- A web search found no existing project or product named "gsts". This is not a trademark search.

### Local rate-limit boundary test

`gsts serve` was run locally with a generated local key and default admission limits (60 attempts/minute, burst 10, 16 in flight). 200 `POST /token` requests with an invalid bearer token were sent with 40 in parallel.

| Observation | Result |
| --- | --- |
| Admitted before the bucket emptied | 10 requests, each 400 `invalid_request` |
| Rejected by admission | 190 requests, 429 `overloaded` with `Retry-After: 1` |
| `/live` during the burst | HTTP 200 |
| 20 requests after 61 seconds | 10 admitted, 10 rejected (the bucket refills to the burst size, not beyond) |
| Bearer value in logs | Absent; 200 `overloaded` denials logged |

This exercises the admission path only. It does not measure GitHub or KMS latency, Cloud Run scaling, or fleet-wide behaviour.

### Local fault injection

- With `GSTS_GITHUB_API_URL` pointing at a closed port, the process started, `/live` returned 200 and `/ready` returned 503 `{"ok":false}`; startup App-permission introspection logged `app_permissions_unavailable` and did not block serving.
- The unit fault matrix (`TestExchangeFailures`, `TestCanceledCleanup`, `TestOrgTrustRevokeFailureStillFailsClosed`) covers policy fetch failure, revocation failure, GitHub rate limiting, KMS signing failure, request cancellation during the policy read, and an undeliverable caller response, asserting the temporary read token is revoked on each path.

Live KMS and GitHub outages against Cloud Run have not been injected.

### Security review

A static, read-only security review of `v0.2.0-alpha.1` was performed with Codex (an automated reviewer; this is not a human third-party audit). It examined OIDC verification, policy parsing and matching, admission, temporary read-token cleanup, the GitHub client, signing and KMS import, configuration and startup, and the GitHub Action client, and reported no concrete issue in those areas except the following, all fixed in `v0.2.0`:

| Severity | Finding | Fix |
| --- | --- | --- |
| Medium | The org trust file and the identity policy were fetched by independent default-branch reads, so two revisions could be combined | Each exchange resolves the default-branch head commit once per repository and reads every file at that commit; the commit is logged |
| Low | A minted caller token was not revoked when the response could not be delivered | gsts revokes the token it minted if the request was cancelled before the write or the write fails |
| Low | A cancelled request during a cold JWKS fetch left the issuer throttled with an empty key cache for 30 seconds | The refresh runs on its own deadline, independent of the caller, and the throttle is applied after it completes |

An earlier Codex review of the v0.2 feature branch found four issues (signature re-encoding bypass of replay protection, the org-trust read-token fallback, live-entry eviction, an expiry race); those were fixed before `v0.2.0-alpha.1`.

### Live acceptance of the v0.2 features

**Pending.** Before tagging `v0.2.0`, run the following against a deployment of the `v0.2.0` candidate image and record the results here:

- Same ID token exchanged twice on one instance: second response is 403 `token_replayed`.
- `GSTS_ORG_TRUST_FILE` enabled, trust file allowing only the Google issuer: a GitHub Actions token is rejected with 403 `issuer_not_trusted`; a Google token succeeds; an organization without the file still succeeds.
- A policy with `claim = { repository_id = "..." }`: the matching workflow succeeds and a workflow from another repository is rejected with 403 `policy_mismatch`.
- `/ready` returns 200 and an ordinary exchange succeeds on the candidate image, confirming the pinned-commit policy reads work against GitHub.

### Not covered

- Long-running continuous operation.
- Live KMS and GitHub fault injection.
- A human third-party security audit.

## Live acceptance record: v0.1.0-alpha.2

This records the maintainer's live acceptance test of `v0.1.0-alpha.2`. It is a report of what was observed, not a security review or a production-readiness statement. Project identifiers, organization names and URLs are intentionally omitted.

### Version and environment

- Version: `v0.1.0-alpha.2`.
- Environment: Cloud Run with Cloud KMS.
- Deployed image: pinned by digest, with the same revision and version as the public release.
- Services: five, separated by App, key, audience and policy.

### Verified live

- The GitHub App private key was imported into Cloud KMS, and GitHub App authentication with KMS signing succeeded. The App, installation and permissions it authenticated against were as expected.
- `/live` and `/ready` returned HTTP 200 on all five services.
- OIDC-to-GitHub installation token exchange succeeded with six Google service account identities. Narrowing to the requested read permissions and explicit token revocation after use (HTTP 204) were confirmed.
- GitHub Actions OIDC exchange succeeded using the official GitHub Action. The issued token could access only the one specified repository, and the token was revoked by the post-job cleanup.
- Creating a branch and a pull request through the GitHub API with a gsts-issued token succeeded.
- Denials behaved as intended:
  - an audience that is not allowed: HTTP 403 `audience_not_allowed`;
  - an organization outside the allowed scope: HTTP 403 `scope_not_allowed`;
  - a valid OIDC token from a different workflow: HTTP 403 `policy_mismatch`.
- On the four services that allow only the Google issuer, a GitHub Actions identity was rejected with HTTP 401 `invalid_token`.

### Verified offline

- Policy CLI allow/deny fixtures: claims that should match were allowed, and claims with a different issuer, subject, audience, repository ID, owner ID, ref, workflow or event were denied.
- The release verification and image publication CI succeeded.

### Conclusion

Within the scope verified, KMS signing, OIDC exchange, policy allow/deny decisions, narrowing of permissions and repositories, and token revocation worked as intended.

### Not covered

- Rate-limit boundary load testing.
- KMS and GitHub fault injection.
- Long-running continuous operation.

Features added after `v0.1.0-alpha.2` (per-instance replay prevention, the organization trusted-issuer allowlist and the exact-match `claim` table) were not part of this test and have not been live-tested. No independent security review has been done.
