# Security

This project is pre-release. Do not infer a security audit or a successful production deployment from passing local tests.

## Reporting a vulnerability

Do not include credentials, private keys, or tokens in issues. Once private vulnerability reporting is enabled for the public repository, use [GitHub's private report form](https://github.com/sakajunquality/gsts/security/advisories/new). If that form is unavailable, contact the maintainer through an existing private channel; a public issue may request a private contact without disclosing exploit details.

## Trust boundaries

- The GitHub App key can authenticate as the App across all its installations. The gsts runtime's signing permission is consequently sensitive even though it cannot export key material. Restrict deployment, runtime IAM, and code changes.
- Repository default-branch writers can change repo policies. Org policy-repository writers can grant org-wide authority. Protect both with reviews, CODEOWNERS, and rulesets suitable for your organization.
- Permission ceilings come from the policy and GitHub App installation. Repository policies cannot grant organization-level permissions. Org permissions are not constrained by a `repositories` list.
- `[google] project` includes future matching service accounts. Email selectors can match a recreated account with the same email. Add numeric `subject` when immutable identity is needed.
- Audience overrides opt into accepting tokens issued for another audience. Avoid broad audience patterns. `azp` is not checked.
- Service account impersonation permissions can allow another principal to mint a valid caller ID token. Control those permissions outside gsts.
- No token replay database exists. Token theft permits replay until expiry. A `max_token_lifetime` policy restricts accepted ID-token lifetime; it does not shorten GitHub's returned token lifetime.
- Signed tokens with an allowed issuer can cause policy lookup requests before audience authorization because policies can override audiences. The App's GitHub rate limit is shared; use org allowlists and monitor denied exchanges. There is no application-level abuse quota in v0.1.
- Temporary read tokens are revoked on normal success/failure paths, including request cancellation. An outage or process crash can leave them valid until expiry. Network uncertainty during token creation can also orphan a token. There is no exactly-once guarantee.
- HTTP responses do not reveal claim mismatch details. Logs contain authenticated identity information and need access controls, retention policy, and review.

## Key handling

GitHub generates the private key and downloads it as PEM. Initial import necessarily handles plaintext outside KMS. The import command performs wrapping in memory, but managed-language memory is not guaranteed to be securely erased. Choose a trusted import machine and account for backups and snapshots when deleting PEM copies. Never commit PEM, Terraform state, ADC files, or tokens.

Production configuration uses KMS only. `file` and `env` are explicitly gated by `GSTS_ALLOW_INSECURE_KEY=1` and are for local development. Do not set this flag in deployed services.

## Before a public release

Enable private vulnerability reporting, complete live Cloud Run / KMS / GitHub acceptance, review dependencies and container provenance, verify package visibility, and arrange a security review of the authorization and cleanup paths. The CI workflow never requires production credentials.
