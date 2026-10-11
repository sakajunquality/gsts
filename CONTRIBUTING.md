# Contributing

Use Go 1.26.9+ and Terraform 1.7+ for mocked plan tests (the module supports 1.6+). Keep authentication and authorization changes small enough to audit. Cover attacks and observable behavior, including failure and cancellation paths. Tests must not require real keys, cloud credentials, or GitHub tokens.

```sh
make check
make terraform-check
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
docker build -t gsts:dev .
docker run --rm gsts:dev version
```

There is no generated SDK or service state to migrate. The main boundaries are `oidc` (authenticated claims), `policy` (authorization), `github` (scoped API access), `signing` (App JWT), and `server` (exchange orchestration). Keep bearer tokens out of logs/errors. Test regular and org policies when changing scope semantics.

## Release

CI runs tests, race detection, vet, a vulnerability scan, Terraform validation, and a container build. The image workflow runs the checks again against a tag on `main`, builds a digest-addressed candidate for linux/amd64 and linux/arm64, checks the executable version on both platforms, and promotes that same image to GHCR with provenance and an SBOM. No deployment is performed.

Push a `vMAJOR.MINOR.PATCH` tag for a stable release, or `vMAJOR.MINOR.PATCH-alpha.N` / `-beta.N` / `-rc.N` for acceptance testing. Stable releases also update `latest`; prereleases do not. Publish stable versions in increasing order. The `Release image` workflow can also be dispatched on `main` with an existing tag as its `version` input. Never move a published Git tag; pin the image digest for deployments because rerunning a build can change its digest.

Before stable tagging, complete the live runbook and security review and update CHANGELOG. Prerelease images may be published before live acceptance, with that limitation stated explicitly. On first publication, change the `gsts` container package visibility to Public in GitHub package settings; repository visibility alone does not make a package public. Verify an anonymous pull after changing it. Source archives on tags contain the Terraform module. Standalone binary releases are not automated in v0.1.

Dependency updates should include `go mod tidy` and the relevant checks. GitHub Actions are pinned to commits; Dependabot opens update PRs. This repository uses Apache-2.0; contributions are accepted under the same license.
