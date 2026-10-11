# Trust policies

Policies are read from the repository's default branch on every exchange. No policy cache or caller-selected ref is used. A repo scope reads `.github/gsts/<identity>.sts.toml` in that repo. An org scope reads the same path in its `.github` repository (configurable). That repository must be accessible to the GitHub App.

## Schema

| Field | Meaning |
| --- | --- |
| `issuer` / `issuer_pattern` | Exact issuer / anchored regex. At least one required unless `[google]` is present. |
| `subject` / `subject_pattern` | Exact `sub` / anchored regex. At least one required unless `[google]` is present. |
| `audience` / `audience_pattern` | Match an audience in `GSTS_ALLOWED_AUDIENCES`; defaults to `GSTS_IDENTIFIER` |
| `claim_pattern` | Map of claim names to regexes. All must match. String, boolean, and numeric scalar claims are supported. |
| `max_token_lifetime` | Positive upper limit in seconds for `exp - iat`; 0/omission means no extra limit |
| `[permissions]` | Nonempty permission map, values `read` or `write` |
| `repositories` | Root field, org-only list of repositories; omission permits all installed repositories |
| `[google]` | One Google account selector, described below |

All supplied exact and pattern constraints are ANDed. Regexes use Go RE2 syntax and are wrapped in `^(?:...)$`. Backreferences and lookaround are unsupported. TOML literal strings (`'...'`) are useful for regexes containing backslashes. Unknown fields are rejected so a misspelled constraint cannot silently disappear.

## Google service accounts

`[google]` requires exactly one of:

- `service_account`: exact service account email.
- `service_account_pattern`: anchored regex for the email.
- `project`: all `*@PROJECT.iam.gserviceaccount.com` identities.

Each selector also requires issuer `https://accounts.google.com` and boolean `email_verified = true`. Email comparison is case-sensitive. The `project` selector describes the email domain, not an independently verified project claim, and does not include default Compute Engine service accounts (`...@developer.gserviceaccount.com`). Use an exact selector or raw claims for those identities. `project` gives access to **every matching account**, including accounts added later.

```toml
[google]
service_account_pattern = 'deploy-.*@my-project\.iam\.gserviceaccount\.com'

[permissions]
contents = "read"
```

An explicit `issuer`, `subject`, or pattern still applies alongside `[google]`. A numeric `subject` pins the service account's immutable identity and prevents a newly created account with a reused email from matching:

```toml
subject = "112233445566778899000"

[google]
service_account = "deploy@my-project.iam.gserviceaccount.com"

[permissions]
contents = "read"
```

An email-only shortcut and a policy pinning a numeric subject are therefore **not strictly equivalent**. `email_verified` cannot be the string `"true"` for the shortcut. In raw `claim_pattern`, boolean values are rendered as `true`/`false`.

## GitHub Actions

```toml
issuer = "https://token.actions.githubusercontent.com"
subject = "repo:example-org/infra:ref:refs/heads/main"
claim_pattern = { repository_owner = "example-org" }

[permissions]
contents = "read"
```

The workflow needs `id-token: write` to request an OIDC token with gsts's audience. Environment-based subjects have a different format; match the subject actually issued for the workflow. Use additional claims such as repository ID where appropriate to avoid name-reuse ambiguity.

## Organization scope

```toml
repositories = ["infra", "api"]

[google]
service_account = "ci@my-project.iam.gserviceaccount.com"

[permissions]
contents = "read"
```

Call with `{"scope":"example-org","identity":"ci","repositories":["infra"]}`. The result is limited to `infra`. Empty arrays are rejected; they never mean "all repositories".

Repository policies cannot authorize organization-wide permissions such as `members` or `organization_secrets`. New/unrecognized permission names require an org policy until their repository scope is reviewed in gsts. An org-level permission remains organization-wide even if `repositories` narrows repository access. Protect org policy write access accordingly.

The GitHub App must have `contents:read` to load policies, plus every permission a policy can grant. At startup, gsts tries to read the App permission set and logs a warning when a policy exceeds it. Failure to fetch this diagnostic snapshot does not prevent bootstrap. GitHub remains authoritative and may reject token issuance with 422. This check does not discover or pre-read every policy in the organization.

Before deploying policies, run the [offline validate/test CLI](policy-cli.md) in repository CI. Custom audience policies also require a matching entry in the service's `GSTS_ALLOWED_AUDIENCES`.
