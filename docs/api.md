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
| 403 | `audience_not_allowed` | No audience in the service allowlist; rejected before KMS/GitHub |
| 403 | `token_replayed` | This ID token was already used in an exchange attempt on this instance (including attempts that failed after verification) and has not expired; rejected before KMS/GitHub |
| 403 | `scope_not_allowed` | Org allowlist rejection |
| 403 | `policy_mismatch` | Audience/identity/claim mismatch or excessive requested scope |
| 403 | `invalid_policy` | Invalid TOML, missing constraints, or invalid permission scope; also an invalid [organization trust file](policies.md#organization-trusted-issuers) |
| 403 | `issuer_not_trusted` | `GSTS_ORG_TRUST_FILE` is enabled and the organization's trust file does not allow the token's issuer |
| 404 | `not_found` | Installation or policy lookup returned 404 |
| 429 | `overloaded` | Local concurrency or request-rate limit, or the replay store is full |
| 429 | `rate_limited` | GitHub primary or secondary rate limit |
| 502 | `upstream_error` | GitHub, OIDC provider, or KMS failure; includes temporary-token revocation failure |

GitHub 422 (for example, the App lacks a requested permission) is an upstream error. The request is not retried automatically: retrying token creation can mint extra tokens. Use bounded backoff for safe retries and never assume a failed network response means GitHub created no token.

## GET /live and GET /ready

`/live` reports that the process is serving without contacting dependencies. `/ready` signs a fresh App JWT and authenticates to GitHub, returning 200 or 503. Readiness results are cached for 10 seconds and checks have a 5-second timeout. Use `/live` for startup/liveness, and `/ready` for dependency monitoring. `/healthz` has been removed to avoid Cloud Run's reserved-path conflicts; update existing monitors. See [health probes](health.md).

## Replay protection

Unless `GSTS_REPLAY_PROTECTION=off`, each instance accepts a given ID token (identified by a SHA-256 over its decoded header, payload and signature bytes, so re-encoding the signature does not yield a new token) at most once, checked after signature, timestamp and service-audience verification and before any KMS or GitHub call. A client that retries after an ambiguous failure (timeout, dropped response, 5xx) must mint a fresh ID token, because the previous one has been consumed even if the exchange failed. The store is in memory and per instance: it is not shared across Cloud Run instances or restarts, so the same token may still be accepted once by each instance. It holds at most `GSTS_REPLAY_MAX_ENTRIES` live tokens; when full, exchanges are refused with 429 `overloaded` and `Retry-After` until entries expire, because evicting a live entry would make that token replayable. A token that expires between verification and the replay check is rejected with 401 `invalid_token`.

## Admission and retry controls

The service allowlist `GSTS_ALLOWED_AUDIENCES` defaults to `GSTS_IDENTIFIER`. After identity verification and before signing or any GitHub call, a token must contain an allowed audience. Policies can match only audiences in that intersection; they cannot expand the service allowlist. Deployments with custom policy audiences must explicitly list them. A listed audience still needs to satisfy the policy.

Exchange attempts (including invalid credentials) share a per-instance token bucket and concurrency cap. Defaults are 60 attempts/minute, burst 10, and 16 in-flight requests. Rejected admission returns 429 `overloaded` with `Retry-After` seconds before OIDC/KMS/GitHub calls. This bounds each process, not a fleet-wide quota or per-identity fairness. Configure limits with your GitHub quota and Cloud Run instance cap in mind; fresh instances start with a full burst. Health probes use a separate bounded cache.

GitHub rate-limit responses include normalized `Retry-After` when available. Otherwise primary-limit reset time is converted to seconds, with 60 seconds as the fallback. gsts never automatically retries exchange or token creation. Clients should respect `Retry-After`, use bounded attempts and jitter, and account for ambiguous failures that may already have minted a token.

Every `/token` response has a generated `X-Request-ID` for log correlation; inbound request IDs are not trusted. Logs include per-stage `duration_ms`, safe GitHub request IDs on failures, and the applied policy's repository, path and SHA-256 of fetched bytes. The hash identifies the exact policy contents, not a Git commit or proof of branch protection. Tokens and upstream bodies are never diagnostic fields.
