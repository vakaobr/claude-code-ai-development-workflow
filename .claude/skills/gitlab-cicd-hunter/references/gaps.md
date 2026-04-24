# gaps — gitlab-cicd-hunter

**Source:** Author notes on what the source methodology did NOT cover.

The source (`Guia de Segurança e Auditoria em Pipelines CI_CD GitLab.md`)
focuses on secret exposure, hardcoded credentials, and webhook SSRF.
Coverage gaps worth flagging:

---

## GitHub Actions / Circle CI / Bitbucket Pipelines

The source is GitLab-specific. Parallel patterns exist in other CI/CD
systems — scope and skill name should be extended before applying this
methodology to a non-GitLab stack. Key differences:
- GitHub Actions uses `secrets.FOO` (not `$FOO`), and OIDC integration
  uses GitHub's issuer URL.
- Circle CI has "contexts" as the equivalent of masked vars.
- Jenkins has `withCredentials` + the Credentials plugin.

## Supply-Chain via Compromised Dependencies

The source covers hardcoded secrets and pipeline config but does not
deeply address dependency confusion, typosquatting, or malicious
package updates. A full CI/CD audit should also include:
- `npm audit` / `pip-audit` / `cargo audit` / `go list -json -m all`
  for transitive vulns.
- Dependency Confusion checks — publish a private-named package to
  npm / PyPI as a canary and see if the build resolves it.
- SLSA attestation verification for published artifacts.

## Runner Registration Token Leakage

GitLab runner registration tokens are high-value (register a malicious
runner to intercept jobs). The source covers pipeline tokens
(`CI_JOB_TOKEN`) but not runner-registration token hygiene.

## Merge Request CI Environment Variable Exposure

A forked MR runs in the upstream project's CI context on
"runner_protected" if misconfigured. Protected variables can leak to
code written by the MR author if protection rules are not carefully set.

## Release Artifacts vs Build Artifacts

The source treats both as one category. In practice:
- Build artifacts (transient, job-level) often contain temp tokens.
- Release artifacts (`releases/`) are public and indexed — audit
  checksums, SBOMs, and that no debug binary was published.

## GitLab Pages Misconfigurations

A project's GitLab Pages site (`https://GROUP.gitlab.io/PROJECT/`)
may expose artifacts from a pipeline stage. Not covered by the source.

## Group-Level vs Project-Level CI Variables

A variable at the group level is available to every project in the
group. The source treats variables as per-project; group-level scope
is a larger blast radius.

## Scheduled Pipelines

Pipelines that run on a schedule can be abused — a scheduled pipeline
under the account of a now-offboarded employee can still run. Audit:

```bash
curl -H "PRIVATE-TOKEN: $TOKEN" \
     "https://gitlab.example/api/v4/projects/$PID/pipeline_schedules"
```

The source does not discuss scheduled-pipeline drift.

## Secrets in Merge Request Descriptions

A developer pastes a debug log (with an access token) into an MR
description to ask for review. The source notes issues/PRs as sources of
leaked secrets but doesn't emphasize MR descriptions as a separate
channel — which is often richer than issue bodies.

## Container Registry Scanning Coverage

The source mentions container scanning but not:
- Registry-level "retention rules" — old images with vulnerabilities
  can persist indefinitely.
- Image signing / cosign / Sigstore verification at deploy-time —
  without it, a compromised registry can inject a malicious image.

## Project-Visibility Changes

A project that was public at commit-time but is now private may still
have public forks. The source mentions honeypot detection but not the
visibility-change-history audit: `/api/v4/projects/:id/audit_events`.
