---
name: social-engineering-hunter
description: "Plans and runs authorized phishing / social-engineering assessments and awareness campaigns to measure the human attack surface — Gophish campaigns (tracked email + benign landing/credential-awareness pages) and, when explicitly approved, evilginx2 reverse-proxy phishing to demonstrate MFA-phishing risk. Builds pretexts, sets up tracking infra, runs the campaign, and reports click/submit/report rates plus awareness findings. Targets PEOPLE, so it requires separate written consent and an approved recipient list beyond normal scope. Captures behavior metrics, NEVER stores real submitted credentials. Requires .claude/security-scope.yaml red_team_ops.social_engineering: approved + se_consent_ref + se_recipient_list. Grounded in redteam-ops."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(gophish:*), Bash(evilginx:*), Bash(evilginx2:*),
  Bash(python3:*), Bash(curl:*), Bash(dig:*), Bash(host:*),
  Bash(openssl:s_client*), Bash(openssl:x509*), Bash(jq:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: social-engineering
  authorization_required: true
  tier: T2
  profile: social-eng
  source_methodology: "redteam-ops (Gophish/evilginx docs, awareness-program practice)"
  service_affecting: false
  red_team_ops: true
  composed_from: [redteam-ops]
---

# Social Engineering Hunter

## Goal

Measure the organization's human attack surface and improve it: run an
authorized phishing / social-engineering campaign, capture how recipients
behave (click / submit / report), and turn that into awareness findings
and training input. Optionally demonstrate MFA-phishing risk with
evilginx2 when explicitly approved. The deliverable is **behavioral
metrics + a teachable narrative**, not harvested credentials.

> This is the most consent-sensitive skill in the stack: it targets
> people, not systems. It runs ONLY with separate written authorization
> naming the campaign and recipient population, and it never retains real
> credentials.

## When to Use

- An authorized phishing simulation / SE assessment / awareness workshop
  is approved: `red_team_ops.social_engineering: approved`,
  `se_consent_ref` set, and `se_recipient_list` provided.
- The client wants to baseline click/report rates or demonstrate
  credential/MFA-phishing risk for training.

## When NOT to Use

- Without explicit written SE consent + an approved recipient list — even
  if general pentest scope exists. Human targeting needs its own sign-off.
- Against individuals not on the approved list, personal accounts, or as
  real account-takeover. This proves susceptibility; it does not breach.
- Vishing/smishing or in-person pretext ops that need separate legal
  review and aren't email/web (out of this skill).

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. If missing/placeholder, halt.
2. Confirm `red_team_ops.social_engineering: approved`, a non-empty
   `se_consent_ref` (the signed authorization), and `se_recipient_list`
   (approved targets). If any is missing, HALT — do not improvise scope.
3. Confirm the sending domain/infra is one you are authorized to use and
   will not damage the client's domain reputation beyond agreement.
4. **Credential-handling rule**: landing pages capture only the FACT of
   submission (and optionally a hash/length), NEVER the real plaintext
   credential. evilginx use requires `red_team_ops.se_evilginx: approved`
   and a documented session-token destruction step post-proof.
5. Append a `running` row to the Skills Run Log.

## Inputs

- `{issue}`, `{consent_ref}`, `{recipients}` (approved list)
- `{pretext}`: the scenario/theme; `{domain}`: authorized sender/landing
- `{mode}`: awareness (benign) | credential-awareness | evilginx (gated)

## Methodology

### Phase 1: Pretext & Infra
1. **Design the pretext + landing.**
   Do: build a realistic-but-ethical pretext aligned to the consent scope;
   create the Gophish email template + a landing page that, on submit,
   shows an awareness/training message. Configure tracking (open/click/
   submit) and a one-click "Report phish" path if the client uses one.
2. **Stand up tracking infra.**
   Do: configure Gophish (sending profile, landing page, tracking),
   sender domain + TLS (`openssl`/`dig` to verify DNS/cert). Keep all
   infra under the engagement, isolated from client production.

### Phase 2: Launch (controlled)
3. **Send to the approved list only.**
   Do: load `se_recipient_list` into Gophish (verify it matches the
   consented population), schedule within the agreed window, throttle to
   avoid mail-system disruption. Never add addresses outside the list.

### Phase 3: MFA-phishing demo (gated, optional)
4. **evilginx2 reverse-proxy demo.**
   Do: ONLY if `red_team_ops.se_evilginx: approved` — stand up evilginx2
   to demonstrate session/MFA-token capture against a CONSENTED test
   account (ideally a seeded canary, not a real exec). Capture the proof
   that MFA was bypassed, then DESTROY the captured session token and
   document the destruction. This demonstrates risk; it is not used to
   access real data.

### Phase 4: Measure & Report
5. **Aggregate behavior.**
   Do: pull Gophish stats — sent / opened / clicked / submitted /
   reported, time-to-click, time-to-report, repeat-clickers (aggregate,
   not to shame individuals). For evilginx, record only "MFA-phishable:
   yes/no" + the destroyed-token note.

## Output Format

Findings append to `.claude/planning/{issue}/07a_SECURITY_AUDIT.md` (or a
campaign report) per `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:
- **CWE**: CWE-1342 / human-factor framing; CWE-308/CWE-287 where MFA
  phishing proves authentication weakness.
- **ATT&CK**: T1566 (Phishing), T1566.002 (link), T1111 (MFA
  interception) for the evilginx demo.
- **Evidence**: aggregate metrics, the pretext + landing screenshots,
  and (for evilginx) proof-of-MFA-bypass + token-destruction note. NO
  real credentials in the report or anywhere.
- **Remediation framing**: security-awareness owner — targeted training
  for clickers, faster reporting workflow, technical controls (DMARC/
  SPF/DKIM, link rewriting, FIDO2/passkeys to resist MFA phishing,
  conditional access).
- Updates `STATUS.md` and the Skills Run Log.

## Quality Check (Self-Review)

- [ ] Written SE consent (`se_consent_ref`) + approved recipient list verified
- [ ] Sent ONLY to the consented population; window/throttle respected
- [ ] No real plaintext credentials stored anywhere (submission-fact only)
- [ ] evilginx used only if separately approved; session token destroyed + logged
- [ ] Metrics aggregated; individuals not singled out for blame in the report
- [ ] Domain-reputation / mail-flow impact stayed within agreement
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **Scope creep via forwards**: recipients forward the phish; only the
  approved list counts. Don't track/act on forwarded-to addresses.
- **Reputation/deliverability**: aggressive sending can blacklist the
  client domain. Use engagement infra, warm sender, throttle.
- **Legal sensitivity**: works councils / jurisdictions (e.g. EU/DE
  employee-monitoring rules) may restrict employee phishing — confirm the
  consent covers the jurisdiction before launch.
- **Credential temptation**: never "just capture to show them". Submission
  metrics make the point; storing real creds creates liability.

## References

- Gophish: https://getgophish.com/ — evilginx2: https://github.com/kgretzky/evilginx2
- SANS Security Awareness; NIST SP 800-50 (awareness/training)
- MITRE ATT&CK: T1566, T1111

## Source Methodology

Grounded in `redteam-ops` (sections 2-3), authored from Gophish/evilginx
documentation and awareness-program practice. Conversion date: 2026-06-28.
