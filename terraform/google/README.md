# Google Cloud module

One `google_cloud_run_v2_service`, one service account (`<name>-runtime`), one KMS key ring and import-only CryptoKey, key-scoped signer IAM, and an optional public invoker binding. Uses only the Google provider; no external modules. Required APIs must already be enabled.

See the [complete deployment runbook](../../docs/deployment.md). The key version is imported by `gsts kms-import`, never via Terraform state. `kms_key_version` is a configured resource path; it is not proof the version has been imported.

| Input | Default |
| --- | --- |
| `project_id`, `region`, `github_app_id`, `identifier`, `image` | Required |
| `name` | `gsts` (4–22 characters) |
| `kms_key_version_number` | `1` |
| `allowed_orgs` | `[]` (all installed orgs) |
| `allowed_issuers` | Google + GitHub Actions |
| `allow_unauthenticated` | `true` |
| `min_instances`, `max_instances` | `0`, `10` |
| `deletion_protection` | `true` |

Outputs: `service_url`, `kms_key`, `kms_key_version`, `service_account_email`.

The KMS key always has `prevent_destroy = true`. Removing that protection is an explicit operator change. Key rings cannot be deleted through the KMS API. The provider lockfile pins the version used to validate this module locally; consuming root modules resolve their own provider lockfile.

`allow_unauthenticated = false` requires separately managed invoker bindings and the two-header approach documented in the runbook. Custom domains and image registries are managed outside this module. For production, pin the image to a digest.

Run `make terraform-check` from the repository root with Terraform 1.7+ to validate and run mocked plan tests without cloud credentials. The module itself supports Terraform 1.6+.

The startup probe uses `/live`, permitting bootstrap before key import. Use `/ready` to monitor fresh KMS signing and GitHub App authentication (10-second result cache). Exchange admission is configured with `allowed_audiences` (empty defaults to `identifier`), `max_concurrent_exchanges` (16), `exchange_rate_per_minute` (60), and `exchange_burst` (10). Budgets are per process: consider `max_instances`, overlapping revisions and GitHub API quota together. Each environment should instantiate its own module and use its own App/key.
