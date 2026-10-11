# Acceptance and release-gate records

## v0.2.0 release gate

This section records the release-gate work for `v0.2.0`, done on 2026-10-11 against `v0.2.0-alpha.1`, the fixes on the `release/v0.2.0` branch, and the `v0.2.0-rc.1` live acceptance. Each item states what was done and what it does not show.

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

### Live acceptance of v0.2.0-rc.1

The maintainer deployed `v0.2.0-rc.1` (release commit `a9d284b0dfc02f8cf7fc919854131b4ab4ce5686`, image index `sha256:71be10e9041f631b39fa89821741492e4f0674e9ede17288a1793d3b99140d97`, verified Linux amd64 image `sha256:ad1ddf36f9cfe03780c943a25d9a1c72761eaf885f154954f87d7d5ea2a5ed42`) to five isolated Cloud Run services with Cloud KMS-backed GitHub App signing. All services became Ready and returned HTTP 200 from `/live` and `/ready`. The deployed digest, issuer/audience settings and replay configuration were checked.

Verified against live services:

- Six Google service-account identities exchanged OIDC ID tokens for installation tokens. Requested read permissions were preserved, and all test tokens were explicitly revoked with HTTP 204.
- The official GitHub Action exchanged GitHub Actions OIDC tokens. The issued token was limited to the intended repository, and post-job revocation succeeded.
- An incorrect audience and an organization outside the allowed scope were rejected with HTTP 403 `audience_not_allowed` and `scope_not_allowed`. Google-only services rejected GitHub Actions identities with HTTP 401 `invalid_token`.
- A valid OIDC token from an unauthorized workflow was rejected with HTTP 403 `policy_mismatch`. Three further attempts with the same token were rejected with HTTP 403 `token_replayed`, confirming that a denied attempt also consumes the token on the observed instance.
- Successful exchange logs from all five new revisions included `policy_commit` values matching the policy repositories' expected default-branch commits.
- Renovate completed a full dry run, including dependency extraction and checksum lookup, without warnings or errors; the Action revoked its installation token afterwards.
- Automated branch and pull-request creation with rc-issued tokens succeeded.
- Seven production runner labels passed identity, credential-isolation and installed-tool checks. All jobs survived the 120-second idle threshold with a 130-second step, and all temporary runner registrations disappeared after completion.

Validation before deployment:

- All 35 infrastructure CI checks passed; the plan changed only the five token services, and all applies succeeded.
- All eight configured policies validated with the rc image, and 20 offline allow/deny fixtures passed.
- 23 Python tests, three Terraform mock tests, workflow lint and formatting checks passed.
- Upstream release-image CI, main CI, Action tests and policy examples passed for the tagged commit. Image version and revision were checked; the amd64 registry mirror retained the upstream digest.

Scope and limitations stated in the report:

- The results confirm the integration paths above, not every v0.2 feature or failure scenario.
- Replay protection was enabled on the GitHub Actions service and explicitly disabled on the four Google-metadata clients to keep reusable ID tokens working. The store is per instance, not a distributed guarantee.
- Organization trusted-issuer enforcement was not enabled in that deployment, and the exact-match `claim` table was not exercised; existing `claim_pattern` policies were used.
- Response-delivery-failure revocation and cancelled-request JWKS refresh were covered by upstream tests, not by live fault injection.
- Long-duration operation, replay-store exhaustion and live policy changes racing an exchange were not tested.

No functional failures were observed in the deployed configuration's acceptance checks. The report does not itself certify the release.

### Not covered

- Live exercise of `GSTS_ORG_TRUST_FILE` enforcement and of the exact-match `claim` table (offline tests only).
- Long-running continuous operation and replay-store exhaustion.
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

Features added after `v0.1.0-alpha.2` (per-instance replay prevention, the organization trusted-issuer allowlist and the exact-match `claim` table) were not part of this test and were not live-tested at that time; see the v0.2.0 release gate above. No independent security review has been done.
