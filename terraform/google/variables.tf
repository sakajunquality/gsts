variable "project_id" {
  description = "Google Cloud project with Cloud Run and Cloud KMS APIs enabled."
  type        = string
}
variable "region" {
  description = "Cloud Run and KMS region."
  type        = string
}
variable "name" {
  description = "Resource name; the service account ID appends -runtime."
  type        = string
  default     = "gsts"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}[a-z0-9]$", var.name))
    error_message = "name must be 4–22 lowercase letters, numbers, or hyphens."
  }
}
variable "github_app_id" {
  description = "GitHub App ID."
  type        = string
  validation {
    condition     = can(regex("^[1-9][0-9]*$", var.github_app_id))
    error_message = "github_app_id must be a positive integer."
  }
}
variable "identifier" {
  description = "Stable audience URL; need not resolve. Avoids a Cloud Run URL dependency cycle."
  type        = string
  validation {
    condition     = can(regex("^https://[^/?#]+[^?#]*$", var.identifier))
    error_message = "identifier must be an HTTPS URL."
  }
}
variable "image" {
  description = "Cloud Run-compatible image URL, preferably pinned by digest. No unreleased default image."
  type        = string
}
variable "kms_key_version_number" {
  description = "Imported key version number; 1 reserves the initial bootstrap version. Change after rotation."
  type        = number
  default     = 1
  validation {
    condition     = var.kms_key_version_number >= 1 && floor(var.kms_key_version_number) == var.kms_key_version_number
    error_message = "Use a positive integer version number."
  }
}
variable "allowed_orgs" {
  description = "Allowed GitHub organizations; empty permits all organizations where this App is installed."
  type        = list(string)
  default     = []
}
variable "allowed_issuers" {
  description = "Enabled issuers from the built-in Google and GitHub Actions allowlist."
  type        = list(string)
  default     = ["https://accounts.google.com", "https://token.actions.githubusercontent.com"]
  validation {
    condition     = length(var.allowed_issuers) > 0 && alltrue([for issuer in var.allowed_issuers : contains(["https://accounts.google.com", "https://token.actions.githubusercontent.com"], issuer)])
    error_message = "Only Google and GitHub Actions issuers are supported in v0.1."
  }
}
variable "allow_unauthenticated" {
  description = "Grant allUsers Cloud Run invoker. False requires separately configured IAM and X-Serverless-Authorization; see docs."
  type        = bool
  default     = true
}
variable "min_instances" {
  description = "Minimum Cloud Run instances."
  type        = number
  default     = 0
  validation {
    condition     = var.min_instances >= 0 && floor(var.min_instances) == var.min_instances
    error_message = "min_instances must be a nonnegative integer."
  }
}
variable "max_instances" {
  description = "Maximum Cloud Run instances."
  type        = number
  default     = 10
  validation {
    condition     = var.max_instances >= 1 && floor(var.max_instances) == var.max_instances
    error_message = "max_instances must be a positive integer."
  }
}
variable "deletion_protection" {
  description = "Protect Cloud Run from accidental Terraform deletion. The KMS key is always protected."
  type        = bool
  default     = true
}
