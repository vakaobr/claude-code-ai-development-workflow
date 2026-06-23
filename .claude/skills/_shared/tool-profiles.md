# Tool Profiles for Security Skills

Every security skill's `allowed-tools` frontmatter field references
one of these profiles. Centralizing profiles means we change the
allowlist in one place if a tool is later deemed unsafe.

## Profile: passive

For reconnaissance, configuration review, and static analysis. No
outbound probes to targets. No Bash at all — forces skills that
"just want to curl one thing" to justify upgrading to `active`.

```yaml
allowed-tools: Read, Grep, Glob, WebFetch(domain:*.in-scope-domain.com)
```

## Profile: active

For skills that produce test traffic against in-scope web apps and APIs.
Bash is allowed but only for the listed tools. Any tool not on the list
is blocked.

```yaml
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  WebFetch,
  Bash(curl:*), Bash(wget:*), Bash(httpx:*), Bash(ffuf:*),
  Bash(gobuster:*), Bash(nuclei:*), Bash(jq:*), Bash(arjun:*),
  Bash(gf:*), Bash(gau:*), Bash(waybackurls:*),
  Bash(nmap:--script=safe*), Bash(nmap:-sV), Bash(nmap:-Pn),
  Bash(dig:*), Bash(host:*), Bash(whois:*),
  Bash(openssl:s_client*), Bash(openssl:x509*)
```

Explicitly forbidden in `active`:
- `rm`, `mv`, `cp` outside planning/
- `sqlmap` (too aggressive by default; upgrade to specialist skill
  with explicit scope approval)
- `metasploit`, `msfconsole`, `msfvenom`
- `hydra`, `medusa`, `john`, `hashcat` (credential attacks off unless
  scope says otherwise)
- `nikto` (noisy, better options exist)
- Anything with `-d` or `--dangerous` flags

## Profile: cloud-readonly

For AWS IAM audit, S3 review, cloud config skills. Restricts AWS CLI
to read verbs only.

```yaml
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(aws:iam get-*), Bash(aws:iam list-*),
  Bash(aws:iam simulate-principal-policy*),
  Bash(aws:s3api get-*), Bash(aws:s3api list-*),
  Bash(aws:s3api head-*),
  Bash(aws:ec2 describe-*),
  Bash(aws:rds describe-*),
  Bash(aws:lambda get-*), Bash(aws:lambda list-*),
  Bash(aws:cloudtrail lookup-events),
  Bash(aws:configservice describe-*),
  Bash(aws:sts get-caller-identity),
  Bash(jq:*), Bash(yq:*)
```

Explicitly forbidden:
- Any `aws * create-*`, `update-*`, `delete-*`, `put-*`, `attach-*`,
  `detach-*`, `assume-role`
- `aws s3 cp`, `aws s3 sync` (no data movement)
- `aws ec2 run-instances` / `terminate-instances`

## Profile: cicd-readonly

For GitLab CI/CD security review. Read-only access to pipeline config,
no ability to trigger runs.

```yaml
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(glab:repo*), Bash(glab:ci list*), Bash(glab:ci view*),
  Bash(glab:ci trace*), Bash(glab:mr list*), Bash(glab:mr view*),
  Bash(glab:issue list*), Bash(glab:issue view*),
  Bash(git:log*), Bash(git:show*), Bash(git:blame*), Bash(git:grep*),
  Bash(yq:*), Bash(jq:*)
```

Explicitly forbidden:
- `glab ci run`, `glab ci retry`, `glab pipeline run`
- `glab mr create`, `glab mr merge`
- `git push`, `git commit`, `git reset`

## Profile: repo-readonly

For secrets-in-code hunting. History + grep only, no index changes.

```yaml
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(git:log*), Bash(git:show*), Bash(git:blame*), Bash(git:grep*),
  Bash(git:diff*), Bash(git:cat-file*), Bash(git:ls-files*),
  Bash(trufflehog:*), Bash(gitleaks:detect*), Bash(gitleaks:protect*)
```

## Profile: recon-webcheck

For the `web-check-recon` skill, which runs a **self-hosted**
`lissy93/web-check` container on demand and reads its local JSON API. It
is the `active` recon profile narrowed to this skill's needs, extended
with on-demand container lifecycle. The only outbound prober is web-check
itself (constrained by the scope gate); `curl` is restricted by the
skill's methodology to the local API (`127.0.0.1:3000`), never to targets.

```yaml
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  WebFetch,
  Bash(docker:compose*), Bash(docker:ps*), Bash(docker:inspect*),
  Bash(docker:logs*),
  Bash(bash:*), Bash(python3:*),
  Bash(curl:*), Bash(jq:*)
```

Explicitly forbidden:
- Pointing web-check at the public `web-check.xyz` instance for any client
  target (discloses the target to a third party; probes from an
  uncontrolled IP).
- Binding the container to anything other than `127.0.0.1`.
- Running the ACTIVE-tier checks (`ports`, `trace-route`, `firewall`,
  `linked-pages`, `quality`, `screenshot`) when the asset's
  `testing_level` is not `active`.
- Running `tls-labs` (public Qualys scan) without explicit scope approval.

## Per-Skill Override

A skill may request a more restrictive subset of its profile by listing
a narrower `allowed-tools` in its own frontmatter. A skill may NEVER
request a broader set than its profile without explicit approval in a
commit message from a human reviewer.
