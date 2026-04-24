---
model: sonnet
---

## Phase 7a: Static Security Audit

You are entering the **Static Security Audit** phase (7a) for issue: `$ARGUMENTS`

> This is the first of up to three security sub-phases:
> - **7a** `/security` — Static analysis (OWASP, STRIDE, dependency scan) **← you are here**
> - **7b** `/security/pentest` — Dynamic pentest via Shannon (staging only)
> - **7c** `/security/redteam-ai` — AI/LLM threat modeling (only if LLMs in stack)
> - Then → `/security/harden` to fix confirmed findings

### Pre-Conditions
- Read `00_STATUS.md` — confirm Review is complete and APPROVED
- Read `03_ARCHITECTURE.md` for system design
- Read `06_CODE_REVIEW.md` for any security-related findings
- Read `.claude/security-scope.yaml` — confirm this asset is in scope

### Delegation Decision

Before running the checklist below, decide whether to delegate to the
`security-orchestrator` agent (which composes the 40 specialist hunter
skills under `.claude/skills/`).

**Delegate to `@security-orchestrator $ARGUMENTS` if ANY of these are true:**

1. `.claude/security-scope.yaml` declares more than 3 assets with
   `testing_level: active`
2. `00_STATUS.md` for this issue has `Risk: High`
3. The user's invocation included "full", "deep", "comprehensive",
   or "orchestrated" (check `$ARGUMENTS` and the command-line intent)
4. `01_DISCOVERY.md` flags any of:
   - Authentication / authorization changes
   - New API endpoints
   - Handling of user-uploaded content
   - Changes to tenant-isolation logic
   - Integration with new third-party services
   - Cryptographic key or secret handling

**If delegating:**
- Invoke `@security-orchestrator $ARGUMENTS`
- Do NOT run the OWASP/STRIDE checklist in parallel — the orchestrator
  supersedes it and produces a superset of findings.
- Wait for the orchestrator's `07a_SECURITY_AUDIT.md` before marking
  Phase 7a complete in `00_STATUS.md`.
- Phase 7a checkbox in `00_STATUS.md` renders as:
  ```
  - [~] Security (orchestrated)
    - [x] Phase 1: Reconnaissance (N skills)
    - [x] Phase 2: Authentication (N skills, N findings)
    - [~] Phase 3: Access Control (in progress)
    - [ ] Phase 4: Injection
    - [ ] Phase 5: Client-side
    - [ ] Phase 6: API
    - [ ] Phase 7: Infrastructure
    - [ ] Phase 8: Cross-cutting
    - [ ] Phase 9: Report
  ```

**Otherwise (small scope, low risk):** proceed with the OWASP/STRIDE
checklist below. The checklist is the fastest path for small/focused
changes and remains the default for M-sized features.

### Instructions

Perform a security-focused audit of the implemented feature. Create `.claude/planning/$ARGUMENTS/07a_SECURITY_AUDIT.md`:

#### 1. Threat Modeling (STRIDE)

For each component/boundary in the feature:

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| **S**poofing | Can someone impersonate a user/service? | ... | ✓/✗ |
| **T**ampering | Can data be modified in transit/at rest? | ... | ✓/✗ |
| **R**epudiation | Can actions be denied without evidence? | ... | ✓/✗ |
| **I**nformation Disclosure | Can sensitive data leak? | ... | ✓/✗ |
| **D**enial of Service | Can the feature be overwhelmed? | ... | ✓/✗ |
| **E**levation of Privilege | Can users gain unauthorized access? | ... | ✓/✗ |

#### 2. OWASP Top 10 Checklist

- [ ] **Injection**: SQL, NoSQL, OS command, LDAP injection vectors
- [ ] **Broken Authentication**: Session management, credential handling
- [ ] **Sensitive Data Exposure**: Encryption at rest/transit, PII handling
- [ ] **XML/XXE**: External entity processing (if applicable)
- [ ] **Broken Access Control**: Authorization checks on every endpoint
- [ ] **Security Misconfiguration**: Default configs, error messages, headers
- [ ] **XSS**: Output encoding, CSP headers, DOM manipulation
- [ ] **Insecure Deserialization**: Object deserialization from untrusted sources
- [ ] **Known Vulnerabilities**: Dependency scanning results
- [ ] **Insufficient Logging**: Security events are logged and auditable

#### 3. Dependency Audit

```bash
# Run available dependency scanners
npm audit                    # Node.js
pip audit                    # Python (if applicable)
```

Report: vulnerability count by severity, remediation steps.

#### 4. Code-Level Security Review

- [ ] Input validation on all external data
- [ ] Output encoding for all rendered content
- [ ] Authentication required on all protected endpoints
- [ ] Authorization checked at the resource level (not just route)
- [ ] Rate limiting on public/sensitive endpoints
- [ ] CORS configured correctly
- [ ] Secrets not hardcoded (env vars or secret manager)
- [ ] SQL queries use parameterized statements
- [ ] File uploads validated (type, size, content)
- [ ] Error messages don't leak internal details

#### 5. Data Privacy

- [ ] PII is identified and handled appropriately
- [ ] Data retention policies are respected
- [ ] User consent flows are correct (if applicable)
- [ ] Data can be exported/deleted on request (GDPR/CCPA)

#### 6. Summary

```markdown
## Security Audit Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | N |
| 🟡 High | N |
| 🔵 Medium | N |
| ⚪ Low | N |

## Verdict: ✓ PASSED / ⚠ CONDITIONAL PASS / ✗ FAILED

### Required Remediations
1. ...

### Accepted Risks
1. ...
```

### Post-Actions
- Update `00_STATUS.md` with static security audit outcome
- **Next steps after 7a:**
  - If staging environment is available → suggest `/security/pentest $ARGUMENTS` (Phase 7b)
  - If the feature involves LLM/AI components → suggest `/security/redteam-ai $ARGUMENTS` (Phase 7c)
  - If no staging/no dynamic testing needed → suggest `/security/harden $ARGUMENTS` to address findings
  - If PASSED with zero findings → suggest `/deploy-plan $ARGUMENTS`

### Quality Gates
- STRIDE analysis covers all new components/boundaries
- OWASP checklist is fully evaluated (not skipped)
- Dependency audit was actually run (not assumed)
- Every finding has a specific remediation or accepted-risk justification
