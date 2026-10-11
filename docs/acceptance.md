# Live acceptance record: v0.1.0-alpha.2

This records the maintainer's live acceptance test of `v0.1.0-alpha.2`. It is a report of what was observed, not a security review or a production-readiness statement. Project identifiers, organization names and URLs are intentionally omitted.

## Version and environment

- Version: `v0.1.0-alpha.2`.
- Environment: Cloud Run with Cloud KMS.
- Deployed image: pinned by digest, with the same revision and version as the public release.
- Services: five, separated by App, key, audience and policy.

## Verified live

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

## Verified offline

- Policy CLI allow/deny fixtures: claims that should match were allowed, and claims with a different issuer, subject, audience, repository ID, owner ID, ref, workflow or event were denied.
- The release verification and image publication CI succeeded.

## Conclusion

Within the scope verified, KMS signing, OIDC exchange, policy allow/deny decisions, narrowing of permissions and repositories, and token revocation worked as intended.

## Not covered

- Rate-limit boundary load testing.
- KMS and GitHub fault injection.
- Long-running continuous operation.

Features added after `v0.1.0-alpha.2` (per-instance replay prevention, the organization trusted-issuer allowlist and the exact-match `claim` table) were not part of this test and have not been live-tested. No independent security review has been done.
