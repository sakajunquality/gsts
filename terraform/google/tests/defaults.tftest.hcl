# Terraform >= 1.7; mocked plans never contact Google Cloud.
mock_provider "google" {}

variables {
  project_id    = "gsts-test-project"
  region        = "asia-northeast1"
  github_app_id = "12345"
  identifier    = "https://gsts.example.com"
  image         = "ghcr.io/example/gsts:v0.1.0"
}

run "default_bootstrap" {
  command = plan

  assert {
    condition     = can(regex("^[a-z][-a-z0-9]{4,28}[a-z0-9]$", google_service_account.gsts.account_id))
    error_message = "The default runtime account ID must satisfy Google's 6–30 character constraint."
  }
  assert {
    condition     = google_kms_crypto_key.gsts.import_only && google_kms_crypto_key.gsts.skip_initial_version_creation
    error_message = "Bootstrap must create an empty import-only key."
  }
  assert {
    condition     = google_cloud_run_v2_service.gsts.template[0].containers[0].startup_probe[0].http_get[0].path == "/live"
    error_message = "Bootstrap must use process liveness, independent of KMS readiness."
  }
  assert {
    condition     = google_kms_crypto_key_iam_member.signer.role == "roles/cloudkms.signerVerifier"
    error_message = "The runtime must have signing permissions only."
  }
}

run "longest_name" {
  command = plan
  variables {
    name = "abcdefghijklmnopqrstuv"
  }
  assert {
    condition     = can(regex("^[a-z][-a-z0-9]{4,28}[a-z0-9]$", google_service_account.gsts.account_id))
    error_message = "The longest resource name must still yield a valid service account ID."
  }
}
