# Offline policy checks

`gsts policy validate` checks a local TOML policy using the same parser as the server. No environment configuration, credentials, network, GitHub installation or KMS key is needed.

```sh
gsts policy validate --policy examples/policies/actions.sts.toml
gsts policy validate --policy examples/policies/org-ci.sts.toml --org
```

The default scope is repository. Supply `--org` for an organization policy; this affects permission and repository-list validation.

`gsts policy validate-trust --file FILE` checks an [organization trusted-issuers file](policies.md#organization-trusted-issuers) with the server's parser (unknown keys, empty lists and invalid patterns are errors). It takes `--file` rather than `--policy` because it is not an identity policy; `--org`, `--identifier` and `--fixtures` do not apply.

```sh
gsts policy validate-trust --file examples/policies/trusted-issuers.toml
```

`gsts policy test` runs an expected allow/deny suite against the server's policy evaluator:

```sh
gsts policy test --policy examples/policies/actions.sts.toml \
  --identifier https://gsts.example.com \
  --fixtures examples/policy-tests/actions.json
```

`--identifier` is required and must be the deployment's `GSTS_IDENTIFIER`, which supplies the default audience constraint. Explicit policy audience constraints still apply. Organization tests also need `--org`.

A fixture suite is a JSON object containing a nonempty `cases` array. Each case has a unique, nonempty `name`, an `expect` value of `allow` or `deny`, and a `claims` object. Numbers retain JSON numeric representation for `claim_pattern` matching. Unknown suite/case fields, malformed JSON, trailing JSON, invalid expectations and malformed identity claims are errors. Claims require nonempty string `iss` and `sub` and a nonempty string or string-array `aud`. Optional `iat`, `exp` and `nbf` must be integer Unix seconds between 1970 and 9999; when both `iat` and `exp` exist, expiration must be later. Invalid fixtures fail before any cases run and cannot satisfy an expected denial. Valid fixtures may omit timestamps to isolate policy matching; a lifetime constraint can then deny them.

Both commands exit nonzero on errors; `test` also exits nonzero whenever an actual decision differs from `expect`, making it suitable for CI. All valid cases are evaluated so the output shows every mismatch.

**An offline `allow` is only a policy match, not authentication or authorization to issue a GitHub token.** The command never verifies JWT signatures, keys, algorithms, issuer allowlists, current-time expiration/not-before validity, GitHub App permissions, installation access, request narrowing or token issuance. Production verifies signatures and timestamps before policy evaluation. Use synthetic decoded claims; never paste live bearer tokens into fixtures. Historical timestamp fixtures remain useful because tests do not use the current clock.

Validation follows `policy.Parse`: it checks schema, required constraints, patterns and scope rules. It does not establish whether a constraint is suitably restrictive or whether an org permission name is recognized by GitHub. Request permission/repository narrowing is outside this fixture format.
