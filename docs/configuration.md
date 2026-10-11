# Server configuration

All settings are environment variables. Invalid configuration prevents startup. An unavailable KMS version does not prevent the server from listening; dependency readiness is reported by `/ready`; `/live` remains available for bootstrap.

| Variable | Default / required | Meaning |
| --- | --- | --- |
| `GSTS_GITHUB_APP_ID` | Required | Positive GitHub App ID |
| `GSTS_IDENTIFIER` | Required | Default audience, HTTPS URL; HTTP permitted for localhost / 127.0.0.1 |
| `GSTS_KEY_SOURCE` | Required | `kms`, `file`, or `env` |
| `GSTS_KMS_KEY` | Required for `kms` | Full numeric CryptoKeyVersion resource name |
| `GSTS_KEY_FILE` | Required for `file` | PEM file path |
| `GSTS_KEY_ENV` | Required for `env` | **Name** of the environment variable containing PEM |
| `GSTS_ALLOW_INSECURE_KEY` | Disabled | Exactly `1` enables local file/env keys; never set in production |
| `GSTS_ALLOWED_ISSUERS` | Google + GitHub Actions | Comma-separated exact issuer URLs; only these two built-in issuers are supported |
| `GSTS_ALLOWED_AUDIENCES` | `GSTS_IDENTIFIER` | Comma-separated exact audience allowlist before KMS/GitHub; policy matching still applies |
| `GSTS_MAX_CONCURRENT_EXCHANGES` | `16` | Positive per-instance in-flight limit (max 10,000) |
| `GSTS_EXCHANGE_RATE_PER_MINUTE` | `60` | Positive per-instance exchange-attempt rate (max 1,000,000), including denied attempts |
| `GSTS_EXCHANGE_BURST` | `10` | Positive token-bucket burst capacity (max 1,000,000) |
| `GSTS_REPLAY_PROTECTION` | `on` | `on` or `off`. When `on`, each ID token is accepted at most once per instance; a second use returns 403 `token_replayed` |
| `GSTS_REPLAY_MAX_ENTRIES` | `100000` | Positive per-instance capacity of the replay store (max 10,000,000). Each entry is a 32-byte hash plus bookkeeping, held until the token's `exp`. When full, the entry expiring soonest is evicted rather than rejecting the request |
| `GSTS_ALLOWED_ORGS` | All installed orgs | Comma-separated org allowlist; case-insensitive |
| `GSTS_POLICY_PATH_PREFIX` | `.github/gsts` | Repository-relative policy directory |
| `GSTS_POLICY_FILE_EXTENSION` | `.sts.toml` | Policy filename suffix |
| `GSTS_ORG_POLICY_REPO` | `.github` | Org-level policy repository |
| `GSTS_GITHUB_API_URL` | `https://api.github.com` | HTTPS API base URL; GHES is not tested |
| `GSTS_LOG_FORMAT` | `json` | `json` or `text`; JSON uses Cloud Logging's `severity` field |
| `PORT` | `8080` | Listening port, on all interfaces |

Built-in issuers:

- `https://accounts.google.com`
- `https://token.actions.githubusercontent.com`

An empty optional environment variable uses its default. Remove an issuer by providing the other issuer alone. Arbitrary issuer discovery is deliberately unsupported until its outbound trust boundary is explicitly defined.

The runtime service account needs `roles/cloudkms.signerVerifier` on the single signing CryptoKey. It does not need import/admin roles. The person importing the key needs separate KMS import-job creation/read, CryptoKey read, key-version import/read permissions and ADC. Enable the Cloud Run and KMS APIs before Terraform.

JSON logs contain `exchange_authorized`, `exchange_denied`, and `exchange_success` events. Authenticated identity fields, scope, identity, reason, installation ID, and effective permissions are logged as applicable. Tokens, authorization headers, PEM material, and upstream HTTP bodies are not logged. Restrict log access because email and subject are identity data.

Limits are in-memory and per instance, with no distributed store. Scaling, restarts and new revisions create new budgets. They protect upstream cost, but are not a fleet-wide quota or tenant fairness. Replay protection is likewise per instance (see [API controls](api.md#replay-protection)). Each successful exchange normally mints two tokens (policy read and caller). See [API controls](api.md#admission-and-retry-controls).

Keep separate Apps, keys and service deployments for each environment. Reuse the [Action](../action/README.md) and [offline policy tools](policy-cli.md) across those deployments. Never broaden one environment's audiences merely to share another environment's identity.
