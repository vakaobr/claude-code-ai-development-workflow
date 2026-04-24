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

## Per-Skill Override

A skill may request a more restrictive subset of its profile by listing
a narrower `allowed-tools` in its own frontmatter. A skill may NEVER
request a broader set than its profile without explicit approval in a
commit message from a human reviewer.
