---
name: ssrf-cloud-metadata-hunter
description: "Specialist skill for chaining confirmed SSRF into cloud-instance-metadata (IMDS) credential theft — AWS IMDSv1 direct probe, AWS IMDSv2 session-token bypass attempts, GCP v1beta1 legacy endpoint probe, Azure metadata probe with required-header bypass techniques, and credential-use handoff to aws-iam-hunter. Use AFTER ssrf-hunter confirms SSRF works and identifies the cloud provider; this skill deep-dives into metadata-service specifics that ssrf-hunter covers only broadly. Produces findings with CWE-918 / CWE-522 mapping, IAM-role JSON evidence, and IMDSv2-enforcement + egress-filtering remediation. Defensive testing only, STOP-AT-PROOF, no account-wide cloud exploration."
model: opus
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  WebFetch,
  Bash(curl:*), Bash(wget:*), Bash(httpx:*), Bash(ffuf:*),
  Bash(gobuster:*), Bash(nuclei:*), Bash(jq:*), Bash(arjun:*),
  Bash(gf:*), Bash(gau:*), Bash(waybackurls:*),
  Bash(nmap:--script=safe*), Bash(nmap:-sV), Bash(nmap:-Pn),
  Bash(dig:*), Bash(host:*), Bash(whois:*),
  Bash(openssl:s_client*), Bash(openssl:x509*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: cloud
  authorization_required: true
  tier: T1
  source_methodology: "Guia Técnico_ Exploração de SSRF em Metadados de Nuvem.md"
  service_affecting: false
  composed_from: []
---

# SSRF → Cloud Metadata Hunter

## Goal

Deep-dive the specific attack chain where a confirmed SSRF lets
the attacker query the target's cloud instance-metadata service
(IMDS) at 169.254.169.254 (AWS/Azure) or
`metadata.google.internal` (GCP) to steal IAM-role credentials,
OAuth service-account tokens, or instance configuration. This
skill assumes `ssrf-hunter` already confirmed basic SSRF
reachability; its job is the per-provider IMDS-specific
methodology: IMDSv1 direct probe, IMDSv2 session-token bypass
attempts, GCP v1beta1 legacy endpoint, Azure
required-header bypass. This skill implements WSTG-INPV-19
(cloud-specific) and maps findings to CWE-918 (SSRF) + CWE-522
(Insufficiently Protected Credentials). The goal is to produce
the handoff artifact to `aws-iam-hunter` (or GCP/Azure
equivalent) with the captured credentials' scope summary.

## When to Use

- `ssrf-hunter` CONFIRMED SSRF against an in-scope target AND the
  target is cloud-hosted (AWS / GCP / Azure).
- `ssrf-hunter` Phase 3 step 4 attempted IMDS and succeeded with
  basic probe — this skill takes over for the deeper bypass
  methodology.
- The orchestrator selects this skill after `ssrf-hunter` flags
  "IMDS reachable, IMDSv2 enforced" to probe bypass paths.

## When NOT to Use

- For finding SSRF in the first place — use `ssrf-hunter`.
- For exploring the captured credentials' permissions in the
  cloud account — use `aws-iam-hunter` (or GCP/Azure
  equivalent).
- For non-cloud-hosted targets — no IMDS to probe.
- For SSRF scenarios where IMDS is explicitly out-of-scope in the
  scope file.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. Cloud-metadata testing requires explicit scope approval:
   - `internal_ssrf_testing: approved` (link-local 169.254.x.x is
     internal) AND
   - `cloud_metadata_testing: approved` (specific authorization
     for IMDS probes)
   If either is absent, halt and request before running any probe.
4. If credentials are recovered, STOP at the proof. Do NOT use
   the credentials to explore the cloud account beyond a single
   `aws sts get-caller-identity` (or GCP/Azure equivalent) to
   confirm the principal. Hand off to `aws-iam-hunter` for
   authorized read-only enumeration.
5. IMDS probe traffic leaves distinctive log entries. Notify the
   security team BEFORE running (or confirm scope approves
   silent runs) so they can distinguish test traffic.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`. Include the cloud provider and the
   upstream `ssrf-hunter` finding ID.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{ssrf_vector}`: the confirmed SSRF endpoint + parameter from
  `ssrf-hunter`
- `{cloud_provider}`: `aws` / `gcp` / `azure`
- `{user_a}`: authenticated session if the SSRF requires auth

## Methodology

### Phase 1: Confirm the SSRF Vector

1. **Replay ssrf-hunter's confirmed vector**
   [Bug Bounty Bootcamp, Ch 13, p. 226]

   Do: Use the exact SSRF parameter that ssrf-hunter confirmed.
   Send a baseline request pointing at the authorized OOB
   listener to verify reachability.

   Vulnerable signal: Baseline OOB hit confirms the SSRF still
   works.

   Record: Baseline in
   `.claude/planning/{issue}/ssrf-metadata-baseline.md`.

### Phase 2: AWS IMDSv1 Direct Probe

2. **Basic IMDSv1 path enumeration**
   [Bug Bounty Bootcamp, Ch 13, p. 226]

   Do: If `{cloud_provider}` is `aws`, inject:
   ```
   http://169.254.169.254/latest/meta-data/
   ```

   Vulnerable response: Response body contains a list of metadata
   categories: `ami-id`, `hostname`, `iam/`, `public-hostname`,
   `instance-id`, etc.

   Not-vulnerable response: Timeout (host-based firewall blocks
   169.254.x.x), 403, or empty response (IMDSv2 enforced).

   Record: Per-path accessibility in
   `ssrf-metadata-aws-v1.md`.

3. **IAM role enumeration**
   [Bug Bounty Bootcamp, Ch 13, p. 86]

   Do: Navigate to:
   ```
   http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ```

   Vulnerable response: Response contains an IAM role name (e.g.,
   `ec2-production-app-role`).

   Record: Role name.

4. **Credential extraction (one-shot)**
   [Bug Bounty Bootcamp, Ch 13, p. 86]

   Do: Fetch:
   ```
   http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}
   ```

   Vulnerable response: JSON blob with `AccessKeyId`,
   `SecretAccessKey`, `Token`, `Expiration`.

   Record: FINDING-NNN Critical. Store the credentials HASHED
   (first/last 4 chars + sha256) — NEVER plaintext.

   **Immediate**: Hand off to `aws-iam-hunter` via
   `aws-iam-targets.md` with the hash reference. Do NOT call
   `aws sts get-caller-identity` from this skill — that's
   `aws-iam-hunter`'s job under its own authorization check.

### Phase 3: AWS IMDSv2 Session-Token Bypass

5. **Probe IMDSv2 enforcement**
   [AWS IMDSv2 Documentation]

   Do: If Phase 2 returned 401 / 403 / `HttpTokens: required`
   error, IMDSv2 may be enforced. Test whether the SSRF allows
   custom HTTP methods and headers:
   ```
   PUT http://169.254.169.254/latest/api/token
   Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
   ```

   If the SSRF supports PUT with custom headers (rare — most
   SSRFs only support GET), the token step works.

   Vulnerable signal: SSRF returns a 56-byte token string.

   Not-vulnerable signal: SSRF rejects non-GET methods or doesn't
   forward custom headers → IMDSv2 is effective.

   Record: IMDSv2 enforcement status.

6. **Use IMDSv2 token for credential access**
   [AWS IMDSv2 Documentation]

   Do: If the token was obtained in step 5, replay the IMDSv1
   credential path WITH the token as a header:
   ```
   GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
   Header: X-aws-ec2-metadata-token: {token}
   ```

   Vulnerable response: Credentials returned even though IMDSv2
   is "enforced" — because the SSRF supports headers.

   Record: FINDING-NNN.

### Phase 4: GCP Metadata

7. **GCP v1beta1 legacy endpoint (no header required)**
   [Bug Bounty Bootcamp, Ch 13, p. 81]

   Do: If `{cloud_provider}` is `gcp`, probe the legacy
   endpoint that doesn't require the `Metadata-Flavor: Google`
   header:
   ```
   http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
   ```

   This endpoint was deprecated in 2020 but may still be enabled
   on older instances.

   Vulnerable response: JSON with `access_token`.

   Not-vulnerable response: 404 (endpoint disabled) or 403
   (header now required even here).

   Record: FINDING-NNN Critical if the legacy endpoint responds.

8. **GCP v1 header-injection bypass attempts**
   [GCP IMDS Security]

   Do: For modern GCP that requires `Metadata-Flavor: Google`,
   try to inject the header via:
   - URL query-param smuggling (`?Metadata-Flavor=Google`) —
     usually ineffective but worth 30 seconds of testing
   - Header-injection via CRLF in the SSRF URL if SSRF has that
     sub-flaw
   - If SSRF supports custom headers directly, just add the
     header

   Vulnerable signal: GCP returns metadata despite the
   expectation that the SSRF can't set the required header.

### Phase 5: Azure Metadata

9. **Azure IMDS probe with required header**
   [Azure IMDS Documentation]

   Do: If `{cloud_provider}` is `azure`, probe:
   ```
   http://169.254.169.254/metadata/instance?api-version=2021-02-01
   Header: Metadata: true
   ```

   The `Metadata: true` header is required — tests similar to
   GCP.

   Vulnerable response: JSON with instance metadata; check
   specifically for `/metadata/identity/oauth2/token` subpath
   which yields service-principal tokens.

   Record: FINDING-NNN if metadata or tokens return.

### Phase 6: Credential-Scope Handoff (NOT Exploitation)

10. **Hand off to cloud-enumeration skill**
    [This skill's boundary]

    Do: Write a summary to
    `.claude/planning/{issue}/aws-iam-targets.md`:
    ```markdown
    # Handoff to aws-iam-hunter (or gcp-iam-hunter / azure-iam-hunter)

    **Upstream finding:** FINDING-NNN from ssrf-cloud-metadata-hunter
    **Credentials obtained:** HASH: {first4}...{last4}...{sha256}
    **Expiration:** {UTC timestamp from JSON}
    **Role:** {role_name}
    **Next step:** Validate principal via `aws sts get-caller-identity`;
                   enumerate permissions via read-only IAM API calls.
                   DO NOT use credentials for any write operation.
    ```

    This skill STOPS here. `aws-iam-hunter` picks up from this
    handoff.

## Payload Library

Full payloads in `references/payloads.md`. Categories:

- **AWS IMDSv1**: `http://169.254.169.254/latest/meta-data/*`
- **AWS IMDSv2 handshake**: PUT to `/api/token` + GET with
  X-aws-ec2-metadata-token header
- **GCP v1beta1**: legacy token endpoint
- **GCP v1 with header**: modern endpoint + `Metadata-Flavor:
  Google`
- **Azure**: `http://169.254.169.254/metadata/instance` +
  `Metadata: true`
- **SSRF-payload variants**: URL encoding + protocol wrappers
  for each provider's path

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-918 (SSRF) + CWE-522 (Insufficiently Protected
  Credentials) + CWE-16 (Configuration) for missing IMDSv2
  enforcement.
- **OWASP**: WSTG-INPV-19. For APIs, API7:2023 (SSRF). A10:2021
  (SSRF) in Top 10 2021.
- **CVSS vectors**: credentials-obtained-via-IMDSv1 —
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`. IMDSv2-bypass when
  SSRF supports headers — same severity. GCP v1beta1 legacy —
  `...AC:L/S:C/C:H/I:H/A:H`.
- **Evidence**: the SSRF request with the IMDS URL, the response
  containing the credentials (with the SecretAccessKey /
  access_token REDACTED — first/last 4 + hash), the cloud
  provider fingerprinting, and the IMDSv2 status.
- **Remediation framing**: platform / SRE engineer. Include:
  - AWS: enforce IMDSv2 via `HttpTokens: required` on every EC2
    instance; also set `HttpPutResponseHopLimit: 1` to block
    container-escape pivots
  - GCP: disable v1beta1 (it's already off by default post-2020
    but confirm)
  - Azure: no simple "v2" equivalent — rely on egress filtering
  - Cross-cloud: egress filter blocking 169.254.169.254 from the
    application subnet except from the IMDS-client process
  - Least-privilege IAM role — limits blast radius if creds are
    ever stolen

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
- `.claude/planning/{issue}/aws-iam-targets.md` — credential
  handoff

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] The upstream `ssrf-hunter` finding is cited in every
      finding
- [ ] Captured credentials are stored HASHED — grep the audit
      for raw `AKIA...` or `ASIA...` patterns; should find zero
      outside the first/last 4 evidence format
- [ ] No `aws sts`, `gcloud`, or `az` command was run with the
      captured credentials (those belong to the downstream
      skill)
- [ ] Post-credential-capture halt was honored — a single
      confirmation per vector
- [ ] IMDSv2 status is documented (enforced / bypassable / not
      applicable)
- [ ] Handoff file to `aws-iam-hunter` was written with the
      required fields
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Simulated IMDS honeypot**: Security teams sometimes run a
  fake IMDS at 169.254.169.254 with bogus credentials to detect
  attackers. If the credentials look suspicious (all-zeros,
  obvious-test-name role) OR if `aws sts get-caller-identity`
  would fail with a distinctive honeytoken signature (done by
  `aws-iam-hunter`, not here), mark as likely honeypot.

- **WAF echo of metadata URL**: A WAF blocks the IMDS probe but
  reflects the `169.254.169.254` URL in its "blocked" error
  message. Reflection is not a successful probe — confirm with a
  second probe that returns metadata-shape JSON.

- **Client-side SSRF**: The SSRF parameter appears to be
  server-side but the URL is actually fetched by the user's
  browser (via an `<img>` or AJAX call). Client-side browsers
  can't reach IMDS — no risk. Distinguish by checking whether
  the fetch appears to come from the target's server IP or the
  user's.

- **IMDSv2 with custom-header support on the SSRF**: The SSRF
  was confirmed as "simple GET only" by ssrf-hunter, but it
  actually supports custom headers under specific parameter
  encoding. Re-test header-forwarding in step 5 before
  concluding IMDSv2 is effective.

- **Expired credentials in the response**: The token has already
  expired (`Expiration` in the past). File as finding anyway —
  next attack attempt could succeed before rotation — but note
  reduced immediate impact.

- **Role with no permissions**: The IAM role exists but has
  `AssumeRolePolicyDocument` that's unusable from the current
  principal context. Still a finding — the credentials were
  exposed — but `aws-iam-hunter`'s enumeration will show zero
  actionable permissions.

## References

- `references/payloads.md` — per-provider payload catalog with
  encoding variants
- `references/remediation.md` — IMDSv2 enforcement CLI snippets
  per provider

External:
- AWS IMDSv2 Guide:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html
- GCP Metadata Security:
  https://cloud.google.com/compute/docs/metadata/protecting-metadata-server
- Azure IMDS:
  https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- CWE-918: https://cwe.mitre.org/data/definitions/918.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Técnico_ Exploração de SSRF em Metadados de Nuvem.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 13 (SSRF to Cloud Credentials)
- OWASP WSTG v4.2 (WSTG-INPV-19, cloud-specific sections)
- AWS / GCP / Azure official IMDS documentation

Conversion date: 2026-04-24
Conversion prompt version: 1.0
