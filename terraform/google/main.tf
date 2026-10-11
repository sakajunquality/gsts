resource "google_service_account" "gsts" {
  project      = var.project_id
  account_id   = "${var.name}-runtime"
  display_name = "gsts runtime"
}
resource "google_kms_key_ring" "gsts" {
  project  = var.project_id
  name     = var.name
  location = var.region
}
resource "google_kms_crypto_key" "gsts" {
  name                          = var.name
  key_ring                      = google_kms_key_ring.gsts.id
  purpose                       = "ASYMMETRIC_SIGN"
  import_only                   = true
  skip_initial_version_creation = true
  version_template {
    algorithm        = "RSA_SIGN_PKCS1_2048_SHA256"
    protection_level = "SOFTWARE"
  }
  lifecycle {
    prevent_destroy = true
  }
}
resource "google_kms_crypto_key_iam_member" "signer" {
  crypto_key_id = google_kms_crypto_key.gsts.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.gsts.email}"
}
locals {
  kms_key_version = "${google_kms_crypto_key.gsts.id}/cryptoKeyVersions/${var.kms_key_version_number}"
  environment = {
    GSTS_GITHUB_APP_ID   = var.github_app_id
    GSTS_IDENTIFIER      = var.identifier
    GSTS_KEY_SOURCE      = "kms"
    GSTS_KMS_KEY         = local.kms_key_version
    GSTS_ALLOWED_ORGS    = join(",", var.allowed_orgs)
    GSTS_ALLOWED_ISSUERS = join(",", var.allowed_issuers)
    GSTS_LOG_FORMAT      = "json"
  }
}
resource "google_cloud_run_v2_service" "gsts" {
  project             = var.project_id
  name                = var.name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = var.deletion_protection
  template {
    service_account = google_service_account.gsts.email
    timeout         = "60s"
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }
    containers {
      image = var.image
      args  = ["serve"]
      ports {
        container_port = 8080
      }
      resources {
        limits = {
          cpu    = "1"
          memory = "256Mi"
        }
      }
      dynamic "env" {
        for_each = local.environment
        content {
          name  = env.key
          value = env.value
        }
      }
      # TCP bootstrap intentionally permits an empty import-only KMS key.
      # Do not wire /healthz into startup/liveness: it reports dependency readiness.
      startup_probe {
        tcp_socket {
          port = 8080
        }
        period_seconds    = 2
        failure_threshold = 30
      }
    }
  }
  lifecycle {
    precondition {
      condition     = var.min_instances <= var.max_instances
      error_message = "min_instances must not exceed max_instances."
    }
  }
  depends_on = [google_kms_crypto_key_iam_member.signer]
}
resource "google_cloud_run_v2_service_iam_member" "invoker" {
  count    = var.allow_unauthenticated ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.gsts.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
