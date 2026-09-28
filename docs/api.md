# HTTP API

## POST /token

Send an OIDC ID token in `Authorization: Bearer <token>` and one JSON object:

```json
{
  "scope": "example-org/infra",
  "identity": "deploy",
  "permissions": {"contents": "read"}
}
```

| Field | Required | Behavior |
| --- | --- | --- |
| `scope` | Yes | `org/repo` for repo policy, `org` for org policy. Personal-account installations are not supported in v0.1. |
| `identity` | Yes | Policy filename without extension; a single safe filename, never a path |
| `permissions` | No | Subset of policy permissions. A write permission may be reduced to read. Empty maps are denied. |
| `repositories` | No | Org scope only; subset of the policy list, or any installed repositories if the policy omits its list. Empty lists are denied. Maximum 500 entries. |

Unknown fields, oversized bodies (16 KiB), and trailing JSON are rejected. `ref`, branch, installation ID, and policy contents cannot be supplied by the client.

The successful response is HTTP 200, with `Cache-Control: no-store`:

```json
{"token":"ghs_...","expires_at":"2026-09-25T10:00:00Z","permissions":{"contents":"read","metadata":"read"}}
```

`expires_at` and effective `permissions` come from GitHub. GitHub may include implicit `metadata:read`. Installation tokens expire on GitHub's schedule; gsts does not issue refresh tokens or extend token lifetime. A caller owns its returned token and can revoke it via GitHub when finished.

## Errors

```json
{"error":"access denied","reason":"policy_mismatch"}
```

Clients should branch on `reason`, not the human-readable `error`. Claim mismatch details are logged only.

| HTTP | Stable `reason` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Invalid body, scope, auth header, or malformed JWT |
| 401 | `invalid_token` | Disallowed issuer, invalid signature/algorithm, missing identity claims, invalid/expired timestamps |
| 403 | `scope_not_allowed` | Org allowlist rejection |
| 403 | `policy_mismatch` | Audience/identity/claim mismatch or excessive requested scope |
| 403 | `invalid_policy` | Invalid TOML, missing constraints, or invalid permission scope |
| 404 | `not_found` | Installation or policy lookup returned 404 |
| 429 | `rate_limited` | GitHub primary or secondary rate limit |
| 502 | `upstream_error` | GitHub, OIDC provider, or KMS failure; includes temporary-token revocation failure |

GitHub 422 (for example, the App lacks a requested permission) is an upstream error. The request is not retried automatically: retrying token creation can mint extra tokens. Use bounded backoff for safe retries and never assume a failed network response means GitHub created no token.

## GET /healthz

HTTP 200 `{"ok":true}` means the signer can supply an App JWT, possibly from cache. HTTP 503 `{"ok":false}` means signing is unavailable. This is signing readiness, not an end-to-end GitHub/JWKS health check. Use a TCP startup probe so an empty import-only key can bootstrap. Unknown routes and unsupported methods use normal HTTP 404/405 responses.
