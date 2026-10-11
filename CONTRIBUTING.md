# Contributing

Use Go 1.26.8+ and Terraform 1.7+ for mocked plan tests (the module supports 1.6+). Keep authentication and authorization changes small enough to audit. Cover attacks and observable behavior, including failure and cancellation paths. Tests must not require real keys, cloud credentials, or GitHub tokens.

```sh
make check
make terraform-check
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
docker build -t gsts:dev .
docker run --rm gsts:dev version
```

There is no generated SDK or service state to migrate. The main boundaries are `oidc` (authenticated claims), `policy` (authorization), `github` (scoped API access), `signing` (App JWT), and `server` (exchange orchestration). Keep bearer tokens out of logs/errors. Test regular and org policies when changing scope semantics.

## Release

CI runs tests, race detection, vet, a vulnerability scan, Terraform validation, and a container build. The image workflow validates the code again and publishes a multi-platform GHCR image only on an explicitly pushed `vMAJOR.MINOR.PATCH` tag. No deployment is performed. Image tags and `org.opencontainers.image.revision` identify the source.

Before tagging, complete the live runbook and security review, confirm the package's intended visibility, update CHANGELOG, and pin deployment image digests. A private repository/package remains private until its owner changes visibility; the workflow does not change repository or package visibility. Source archives on tags contain the Terraform module. Standalone binary releases are not automated in v0.1.

Dependency updates should include `go mod tidy` and the relevant checks. GitHub Actions are pinned to commits; Dependabot opens update PRs. This repository uses Apache-2.0; contributions are accepted under the same license.
