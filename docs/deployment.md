# Deploy on Google Cloud

This runbook is the live v0.1 acceptance procedure. Complete it in a test project before production. The repository's local checks do not assert that these cloud steps have already run.

## 1. Create the GitHub App

Create an App owned by your organization. Disable webhooks; gsts has no webhook handler. Grant repository `contents:read` (policy reads) plus the permissions you intend to grant callers. GitHub includes metadata read access. Avoid unnecessary organization permissions.

Record the **App ID**. Generate a private key under the App's settings and save the downloaded PEM on the import operator's machine. GitHub generates the key pair; this flow does not upload a KMS-generated public key to GitHub. See [GitHub's instructions](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps).

Install the App on the organization and selected target repositories. For org-level policies, include the `.github` policy repository. Installation can also be done after KMS bootstrap.

## 2. Prepare Google Cloud and an image

Install Go, Terraform, gcloud, and Docker. Authenticate as an operator allowed to manage Cloud Run, service accounts, IAM, and KMS. These permissions are separate from the runtime's signing-only permissions.

```sh
export GSTS_PROJECT=my-gcp-project
export GSTS_REGION=asia-northeast1
gcloud config set project "$GSTS_PROJECT"
gcloud auth application-default login
gcloud services enable run.googleapis.com cloudkms.googleapis.com iam.googleapis.com
make build
```

Use a released **public** image such as `ghcr.io/sakajunquality/gsts:<published-version>`, preferably by digest. There is no release implied by this repository snapshot. Cloud Run supports public GHCR images directly; a private GHCR image requires an Artifact Registry remote repository or a copied image. See [supported registries](https://docs.cloud.google.com/run/docs/deploying#supported_container_registries_and_images).

For testing while this repository/package is private, build into an existing Artifact Registry Docker repository, or create a development repository:

```sh
gcloud services enable artifactregistry.googleapis.com
gcloud artifacts repositories create gsts-images \
  --repository-format=docker --location="$GSTS_REGION"
gcloud auth configure-docker "$GSTS_REGION-docker.pkg.dev"
export GSTS_IMAGE="$GSTS_REGION-docker.pkg.dev/$GSTS_PROJECT/gsts-images/gsts:dev"
docker buildx build --platform linux/amd64 -t "$GSTS_IMAGE" --push .
```

Artifact Registry here is deployment storage, not a runtime service dependency; the Terraform module does not create it. The publisher and Cloud Run service agent need appropriate image access. A public release can use GHCR directly.

## 3. Apply Terraform once

Create a deployment directory outside this source checkout, with `main.tf` based on:

```hcl
provider "google" {
  project = "my-gcp-project"
  region  = "asia-northeast1"
}

module "gsts" {
  source = "/absolute/path/to/gsts/terraform/google"

  project_id    = "my-gcp-project"
  region        = "asia-northeast1"
  github_app_id = "12345"
  identifier    = "https://gsts.example-org.example"
  image         = "asia-northeast1-docker.pkg.dev/my-gcp-project/gsts-images/gsts:dev"
  allowed_orgs  = ["example-org"]
}

output "service_url" {
  value = module.gsts.service_url
}
output "kms_key" {
  value = module.gsts.kms_key
}
output "kms_key_version" {
  value = module.gsts.kms_key_version
}
```

`identifier` is an audience string; it need not resolve in DNS. Choose one stable URL and use it when acquiring caller ID tokens. The service can still be reached at its generated `run.app` URL. This avoids an audience/service-URL cycle on initial apply. Custom domains can be configured separately; the minimal module does not create domain mappings, DNS, or load balancers.

```sh
terraform init
terraform apply
export GSTS_URL=$(terraform output -raw service_url)
export GSTS_KEY=$(terraform output -raw kms_key)
curl --silent --show-error -i "$GSTS_URL/healthz"
```

At this point `/healthz` returns 503 because the key has no version. The server listens and its TCP startup probe passes, so the initial deployment can succeed. Do not use `/healthz` as a startup/liveness probe for this bootstrap flow.

The module grants `allUsers` `roles/run.invoker` by default. gsts performs OIDC authorization itself. If organization policy prohibits that binding, read the IAM section below before applying.

## 4. Import the GitHub key

Run the compiled CLI from the source checkout (or use its absolute path). The operator's ADC needs permission to read the CryptoKey, create/read ImportJobs, import CryptoKeyVersions, and read version state. Use a scoped KMS import/admin role appropriate to your organization; **do not grant these capabilities to the Cloud Run runtime account**.

```sh
/path/to/gsts/bin/gsts kms-import "$GSTS_KEY" /secure/path/app.pem
```

The command creates an import job in the same key ring, waits for it to become active, wraps the PKCS#8 key in memory, imports it, and waits for the version to become enabled. It prints a resource ending in `/cryptoKeyVersions/1` for the first successful import into an empty key. It times out after ten minutes; import jobs expire under KMS's own lifecycle.

Compare the printed version with `terraform output -raw kms_key_version`. If it differs (for example, a previous failed import consumed a version number), set `kms_key_version_number` in the module to the printed version number and apply again. **Do not blindly repeat an import after a timeout:** inspect the job/key versions first; the first request may have succeeded.

If the imported version is the configured version, `/healthz` recovers without redeployment because signing failures are not cached. Check:

```sh
curl --fail --silent --show-error "$GSTS_URL/healthz"
```

Remove the original PEM and any copies after confirming successful import and an exchange. The command never deletes user files automatically. Filesystem deletion does not promise secure erasure on SSDs, snapshots, or backups. Keep this limitation in mind when selecting the import workstation.

## 5. Exchange a real workload token

Commit the [sample policy](../examples/policies/deploy.sts.toml) to the target repo's default branch, changing its email to your caller service account. Protect policy changes with your normal review rules.

Run the metadata/curl example in the [README](../README.md) from that workload, setting the audience to `identifier`. From an operator workstation, a service-account impersonation token can also exercise the endpoint:

```sh
export GSTS_AUDIENCE=https://gsts.example-org.example
ID_TOKEN=$(gcloud auth print-identity-token \
  --impersonate-service-account=deploy@my-project.iam.gserviceaccount.com \
  --audiences="$GSTS_AUDIENCE" --include-email)
curl --fail-with-body --silent --show-error "$GSTS_URL/token" \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scope":"example-org/infra","identity":"deploy"}'
```

Acceptance requires a successful exchange from a **Cloud Run workload service account**, followed by a GitHub API request using the resulting installation token. Also verify a wrong audience and wrong service account are denied, a request cannot exceed policy permissions, and the logs contain the expected audit events without tokens. Impersonation alone is useful for troubleshooting but does not prove metadata-server integration.

## Rotation

1. Generate another private key in the same GitHub App. GitHub registers its public half automatically.
2. Import its PEM into the existing KMS CryptoKey.
3. Set `kms_key_version_number` to the newly printed number and apply. This changes the environment and deploys a new revision.
4. Complete an exchange through the new revision and ensure old revisions have no serving traffic before removing the old GitHub App key. App JWTs can remain cached for several minutes.
5. Retire the old KMS version under your organization's key retention process and remove local PEM copies.

KMS rotation alone does not register a new key with GitHub. The CryptoKey is import-only and protected with Terraform `prevent_destroy`.

## Cloud Run IAM authentication

`allow_unauthenticated = false` omits the public invoker grant; it does not configure caller bindings. Grant selected callers `roles/run.invoker` separately. To preserve the signed ID token gsts needs, send **two headers**:

- `X-Serverless-Authorization: Bearer <Google token whose audience is the Cloud Run service URL>` for the Cloud Run frontend.
- `Authorization: Bearer <ID token whose audience matches the gsts policy>` for gsts.

Cloud Run prioritizes `X-Serverless-Authorization` for its own authentication and may strip the signature from the token it processes. Do not rely on the same `Authorization` header being preserved as a verifiable token after frontend IAM authentication. See [Cloud Run service authentication](https://docs.cloud.google.com/run/docs/authenticating/service-to-service#use_an_id_token).

This is an operator-configured integration, not a separately tested v0.1 IAM mode. The default supported acceptance path is public invoker plus gsts's own OIDC verification.
