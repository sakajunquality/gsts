# gsts GitHub Action

This dependency-free Node.js 24 action requests a GitHub Actions OIDC token, exchanges it at your gsts service, masks both tokens, and revokes the installation token during job cleanup. No App private key is sent to the runner.

```yaml
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: sakajunquality/gsts/action@<reviewed-commit-sha>
        id: gsts
        with:
          service-url: ${{ vars.GSTS_URL }}
          audience: ${{ vars.GSTS_AUDIENCE }}
          scope: example-org/infra
          identity: deploy
          permissions: '{"contents":"read"}'
      - uses: actions/checkout@v4
        with:
          repository: example-org/infra
          token: ${{ steps.gsts.outputs.token }}
          persist-credentials: false
```

Replace the action placeholder with a reviewed full commit SHA. `token` and `expires-at` are outputs. Use the token only within this job. Cleanup runs after subsequent steps, including failed steps; forcibly terminated or lost runners cannot guarantee cleanup. Tokens still expire on GitHub's schedule.

`service-url`, `scope`, and `identity` are required. `audience` defaults to the exact service URL input; set it explicitly when the server identifier or policy audience differs. Optional `permissions` accepts a nonempty JSON object of `read`/`write` values. Optional `repositories` accepts a nonempty JSON array, with at most 500 repository names, for organization scope only. Omitting either narrowing input leaves the server policy in control.

`github-api-url` defaults to `https://api.github.com`. If supplied, it must match the gsts server's API base URL. It supports base paths such as `/api/v3`; GHES is not tested. Configure endpoint inputs only from trusted workflow configuration: these endpoints receive bearer credentials. HTTPS is required, credential/query/fragment URL components are rejected, and redirects are never followed. The runner-provided OIDC URL may contain its existing query parameters.

Use separate GitHub Apps, KMS keys, and gsts deployments for each environment. Configure `GSTS_URL` and `GSTS_AUDIENCE` as GitHub environment variables, and bind each environment's policy to the intended repository, environment subject, audience, and other verified claims. Environment selection alone does not impose an authorization boundary on gsts; the trust policy must enforce it. This action does not provision or select App keys.

Requests have a 30-second deadline, response bodies are bounded, and token exchanges are never retried automatically. Errors include HTTP status but omit upstream bodies. Cleanup state is saved before any token output; if state writing fails, the action attempts immediate revocation. Revocation failures fail the cleanup step; HTTP 401 means the token is already invalid.

Run `npm test` in this directory. Tests use mocked fetch and temporary environment files, with no credentials or network. JavaScript is checked in directly, with no package dependencies or build artifacts. Node.js 24 actions require a compatible runner (v2.327.1 or later).

Protocol references: [GitHub OIDC](https://docs.github.com/en/actions/reference/security/oidc), [action metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax), [workflow state and outputs](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands), and [installation token revocation](https://docs.github.com/en/rest/apps/apps#revoke-an-installation-access-token).
