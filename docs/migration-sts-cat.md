# Migrating sts-cat policies to gsts

gsts follows [sts-cat](https://github.com/sorah/sts-cat) for the `POST /token` request shape and the base TOML field names. This is compatible vocabulary, **not a guarantee of byte-for-byte or semantic parity** (see [Compatibility](design.md#compatibility)). Treat every migrated policy as new: validate it, test it, and review what it allows.

## What is compatible

- The `POST /token` request shape: `scope` and `identity`, plus optional `permissions` and `repositories`. See the [HTTP API](api.md).
- The base TOML field names used by [trust policies](policies.md).
- The existing policy location: set `GSTS_POLICY_PATH_PREFIX=.github/sts-cat` to read policies from `.github/sts-cat` instead of the default `.github/gsts`. `GSTS_POLICY_FILE_EXTENSION` (default `.sts.toml`) and `GSTS_ORG_POLICY_REPO` (default `.github`) can be set if your files or organization policy repository differ. See [configuration](configuration.md).

## Differences and what to change

| Difference in gsts | What to change |
| --- | --- |
| Regexes use Go RE2, not Rust regex syntax. Patterns are wrapped in `^(?:...)$`. | Re-check every `*_pattern` value. Lookaround (`(?=`, `(?!`, `(?<=`, `(?<!`) and backreferences (`\1`) are unsupported and fail validation; rewrite them as plain alternation or character classes, or use an exact field (`subject`, `claim`). Use TOML literal strings (`'...'`) for backslashes. |
| Lifetime limits use the required `iat` claim: `max_token_lifetime` bounds `exp - iat`. There is no `nbf` fallback. | Make sure the issuer's tokens carry `iat`. gsts requires `iat`, `exp`, `iss`, `sub` and `aud` on every token. Fixtures that exercise a lifetime limit must include both `iat` and `exp`. |
| Unknown policy keys are rejected. | Remove or correct any key gsts does not define, including misspellings. `gsts policy validate` reports them. |
| Empty `repositories` lists and empty `[permissions]` maps are denied. | Give every policy a nonempty `[permissions]`. For org policies, either list repositories explicitly or omit `repositories` to permit all installed repositories (prefer the explicit list). |
| Repository policies cannot grant organization permissions. | Move any organization permission (for example `members`) into an org-level policy in the organization's `.github` repository, and validate it with `--org`. `repositories` is a root TOML field and goes before `[google]`. |
| Google email-only shorthand does not pin an immutable numeric subject. | If a policy uses `[google] service_account` (or a pattern or `project`), add a numeric `subject` where a recreated account with the same email must not match. `project` matches every account in that project, including ones added later. |
| Only the Google and GitHub Actions issuers are supported. | Policies for any other issuer cannot be used. Leave `GSTS_ALLOWED_ISSUERS` at its default or restrict it to one of the two. |
| The response includes `expires_at` and `permissions` in addition to the token. | Clients that parse the response strictly must tolerate the extra fields. Do not log the token. |
| The `claim` table (exact-match claims) is a gsts extension. | Optional. Policies that use it are not portable back to sts-cat. Values are type-strict; GitHub Actions emits `repository_id` and `repository_owner_id` as strings. See [Exact claims](policies.md#exact-claims). |

Other gsts behavior to review: the service audience allowlist (`GSTS_ALLOWED_AUDIENCES`, default `GSTS_IDENTIFIER`) is checked before any policy is read, and policy audience constraints can only match audiences in it. Policies are read from the default branch on every exchange.

## Step by step

1. Copy the policy files to the new repository location, or leave them in `.github/sts-cat` and use the path prefix override in step 4.
2. Validate each policy with the server's parser, adding `--org` for org-level policies:

   ```sh
   gsts policy validate --policy path/to/deploy.sts.toml
   gsts policy validate --policy path/to/org-ci.sts.toml --org
   ```

   Fix every error using the table above.
3. For each policy, write a JSON fixture suite with allow cases (the claims you expect) and deny cases (different issuer, subject, audience, repository, ref, workflow and so on), then run it. `--identifier` must be the deployment's `GSTS_IDENTIFIER`:

   ```sh
   gsts policy test --policy path/to/deploy.sts.toml \
     --identifier https://gsts.example.com \
     --fixtures path/to/deploy.json
   ```

   Use synthetic decoded claims, never live tokens. An offline `allow` is only a policy match; it does not verify signatures, timestamps, App permissions or token issuance. See [offline policy checks](policy-cli.md).
4. Deploy gsts with `GSTS_POLICY_PATH_PREFIX=.github/sts-cat` (and the extension or org repository overrides if needed) so existing policies are read in place. Exercise each policy with a real token before relying on it.
5. Optionally, rename `.github/sts-cat` to `.github/gsts` in each repository and remove the `GSTS_POLICY_PATH_PREFIX` override. Make the rename and the configuration change together: policies are read from one prefix only.
