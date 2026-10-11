# Trust policies

Policies are read from the repository's default branch on every exchange. No policy cache or caller-selected ref is used. A repo scope reads `.github/gsts/<identity>.sts.toml` in that repo. An org scope reads the same path in its `.github` repository (configurable). That repository must be accessible to the GitHub App.

## Schema

| Field | Meaning |
| --- | --- |
| `issuer` / `issuer_pattern` | Exact issuer / anchored regex. At least one required unless `[google]` is present. |
| `subject` / `subject_pattern` | Exact `sub` / anchored regex. At least one required unless `[google]` is present. |
| `audience` / `audience_pattern` | Match an audience in `GSTS_ALLOWED_AUDIENCES`; defaults to `GSTS_IDENTIFIER` |
| `claim_pattern` | Map of claim names to regexes. All must match. String, boolean, and numeric scalar claims are supported. |
| `claim` | Table of claim names to exact values (strings, integers or booleans). Every entry must match; the claim must exist and be a scalar of the same type. See [Exact claims](#exact-claims). |
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

The workflow needs `id-token: write` to request an OIDC token with gsts's audience. Environment-based subjects have a different format; match the subject actually issued for the workflow. Use `claim` with `repository_id` and `repository_owner_id` (see [Exact claims](#exact-claims)) to avoid name-reuse ambiguity.

## Exact claims

`claim` pins claims by exact value, avoiding escaped regexes. Every entry is ANDed with all other constraints, and a key may appear in both `claim` and `claim_pattern`; both must hold. Matching is strict and never coerces types:

| Policy value | Matching claim |
| --- | --- |
| string | string, byte-equal |
| integer | JSON number that is an integer and equals the value (`123.5` and `123.0` do not match) |
| boolean | boolean, equal |

Anything else is a mismatch: a different type (a string claim never matches an integer value and vice versa), an array or object claim, or a missing claim. Floats, arrays, tables and datetimes in `claim` are rejected at parse time, as are an empty table and an empty claim name. Denial messages do not include claim values.

**GitHub Actions claim types:** Actions emits `repository_id` and `repository_owner_id` as JSON strings, so write `repository_id = "123"`, not `123`. An integer there would never match. Check the type of the claim you pin against a real token.

```toml
# GitHub Actions: pin immutable IDs (note: strings)
issuer = "https://token.actions.githubusercontent.com"
subject = "repo:example-org/infra:ref:refs/heads/main"
claim = { repository_id = "123456789", repository_owner_id = "987654321" }

[permissions]
contents = "read"
```

```toml
# Google: pin the authorized party
subject = "112233445566778899000"
claim = { azp = "112233445566778899000" }

[google]
service_account = "deploy@my-project.iam.gserviceaccount.com"

[permissions]
contents = "read"
```

For a service account identity token obtained from the metadata server, `azp` is typically the service account's unique numeric ID, the same value as `sub`. Verify this against a real token before relying on it; a wrong value denies every exchange.

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

## Organization trusted issuers

`GSTS_ALLOWED_ISSUERS` is chosen by the deployment operator. An organization can additionally restrict, for its own scopes, which issuers may federate into it by committing a trusted-issuers file to its org policy repository (`GSTS_ORG_POLICY_REPO`, default `.github`). The feature is **opt-in per deployment**: it is active only when the operator sets `GSTS_ORG_TRUST_FILE` to the file's repository-relative path. See [configuration](configuration.md).

```toml
issuers = ["https://accounts.google.com"]
issuer_patterns = ['https://token\.actions\.githubusercontent\.com']
```

- `issuers`: exact issuer URLs. `issuer_patterns`: Go RE2 regexes wrapped in `^(?:...)$`, like policy patterns. Prefer anchored exact hosts with escaped dots; a loose pattern can match more than intended.
- At least one list must be nonempty. `issuers = []` with no patterns is invalid: empty never means "all issuers". Unknown keys are rejected.
- The file is **enforce-only**. It can narrow the deployment allowlist but never adds an issuer the deployment does not accept.
- It applies to every exchange for the organization, repository and org scope alike, and is read from the default branch on every exchange (no cache).

Failure semantics when enabled:

| Situation | Result |
| --- | --- |
| File not found (404), or the org policy repository is missing or not accessible to the App | Organization has not opted in; the exchange proceeds |
| Invalid TOML, unknown key, or no issuers/patterns | 403 `invalid_policy` |
| Token issuer not allowed by the file | 403 `issuer_not_trusted` |
| Any other fetch error | 502 `upstream_error` (rate limits still map to 429 `rate_limited`); fail closed |

The temporary read token is revoked before any of these outcomes is acted on. The read token is created for the policy repository and the org policy repository together. If GitHub rejects that with 404/422 (the org policy repository does not exist or is not installed), gsts requests a token for the policy repository alone and treats the organization as not opted in; this costs one extra call only in that case. Logs record `org_trust_repository`, `org_trust_path` and `org_trust_sha256`. Validate files offline with `gsts policy validate-trust`; see [the CLI](policy-cli.md) and [`examples/policies/trusted-issuers.toml`](../examples/policies/trusted-issuers.toml).

**Security note:** whoever can write to the org policy repository's default branch controls this file, and also controls org-scope policies. Protect that repository accordingly. Removing or renaming the file (or making the repository inaccessible to the App) disables the org restriction, because absence means "not opted in".
