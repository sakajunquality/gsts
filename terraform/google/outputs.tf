output "service_url" {
  description = "Cloud Run endpoint URL."
  value       = google_cloud_run_v2_service.gsts.uri
}
output "kms_key" {
  description = "Pass this CryptoKey name to gsts kms-import."
  value       = google_kms_crypto_key.gsts.id
}
output "kms_key_version" {
  description = "Configured version path; may not exist until the first import."
  value       = local.kms_key_version
}
output "service_account_email" {
  description = "Runtime service account with signing access to this key only."
  value       = google_service_account.gsts.email
}
