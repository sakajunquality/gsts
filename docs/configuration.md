# Server configuration

All settings are environment variables. Invalid configuration prevents startup. An unavailable KMS version does not prevent the server from listening; signing readiness is reported by `/healthz`.

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

The runtime service account needs `roles/cloudkms.signerVerifier` on the single signing CryptoKey. It does not need import/admin roles. The person importing the key needs separate KMS import-job creation/read, CryptoKey read, key-version import/read permissions and ADC. Enable the Cloud Run and KMS APIs before deploying the service.

JSON logs contain `exchange_authorized`, `exchange_denied`, and `exchange_success` events. Authenticated identity fields, scope, identity, reason, installation ID, and effective permissions are logged as applicable. Tokens, authorization headers, PEM material, and upstream HTTP bodies are not logged. Restrict log access because email and subject are identity data.
