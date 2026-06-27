---
name: llm-redteam-hunter
description: "Automated red-teaming of the organization's OWN LLM / inference endpoints using garak and PyRIT. Runs probe batteries for prompt injection, jailbreak / guardrail bypass, harmful-content generation, training-data / system-prompt leakage, and insecure output handling, then normalizes the scanner output into the canonical finding schema mapped to the OWASP LLM Top 10 (LLM01 Prompt Injection, LLM02 Insecure Output, LLM06 Sensitive Info Disclosure, LLM07 System-Prompt Leakage). Complements (does not overlap) the manual /redteam-ai command and security-analyst OBLITERATUS work by adding automated, repeatable scanning. Use when an in-scope endpoint embeds or exposes an LLM. Requires .claude/security-scope.yaml with the target listed under llm_endpoints and llm_redteam: approved. Defensive testing of your own endpoints only."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  WebFetch,
  Bash(garak:*), Bash(python3:-m garak*), Bash(pyrit:*),
  Bash(python3:*), Bash(pip:show*), Bash(curl:*), Bash(jq:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: ai-llm
  authorization_required: true
  tier: T1
  profile: ai-redteam
  source_methodology: "guardian-cli (garak/pyrit integration pattern), MIT"
  service_affecting: false
  composed_from: []
---

# LLM Red-Team Hunter

## Goal

Provide automated, repeatable adversarial testing of LLM endpoints the
organization owns or integrates, using `garak` (vulnerability scanner
for generative models) and `PyRIT` (Microsoft's risk-identification
toolkit). Where the existing `/redteam-ai` command and `security-analyst`
agent do *manual* threat modeling and (for open-weight models)
mechanistic alignment analysis, this skill adds the missing *automated
probe battery* layer and normalizes results into the canonical finding
schema. Findings map to the OWASP Top 10 for LLM Applications.

## When to Use

- An in-scope application embeds or exposes an LLM (chat assistant,
  RAG endpoint, agent with tools, summarizer) and that endpoint is
  listed under `llm_endpoints` in scope with `llm_redteam: approved`.
- The team wants a regression-grade, repeatable scan (e.g. before each
  release) rather than a one-off manual review.
- After `/redteam-ai` mapped the attack surface and you want to confirm
  which theoretical vectors actually fire.

## When NOT to Use

- Manual prompt-injection threat modeling / architecture review — use
  the `/redteam-ai` command and `security-analyst` agent.
- Open-weight model alignment/refusal-geometry analysis — that is the
  OBLITERATUS path in `/redteam-ai`.
- Pointing probes at a third-party provider's public API as the
  "target" (e.g. scanning api.openai.com). Test YOUR endpoint only.
- Any LLM endpoint not declared in `llm_endpoints`.

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. Halt if missing/placeholder.
2. Confirm the exact endpoint URL/identifier appears under
   `llm_endpoints` AND `llm_redteam: approved` is set.
3. Confirm the target is first-party (the org's deployment), not a
   provider's shared infrastructure. If the endpoint host belongs to a
   model vendor, halt and ask.
4. Note any cost ceiling — probe batteries can issue thousands of
   generations. Respect `llm_redteam_max_requests` if set.
5. Append a `running` row to the Skills Run Log.

## Inputs

- `{issue}`: planning folder name
- `{endpoint}`: the in-scope LLM endpoint (URL or local model id)
- `{auth}`: how the harness authenticates to the endpoint (vault ref)
- `{model_context}`: optional — system-prompt structure, tool access,
  output rendering surface (from `/redteam-ai`'s AI components inventory)

## Methodology

### Phase 1: Surface Confirmation
1. Confirm reachability and capability tier of the endpoint: does the
   model have tool/function access, file access, or rendered output?
   (This sets impact — same finding is Medium with no tools, Critical
   with code execution. Cross-ref the matrix in `offensive-security` →
   "Prompt Injection Severity Matrix".)

### Phase 2: garak Probe Battery
2. **Run garak** against the endpoint via the appropriate generator.
   Example (REST generator):
   ```
   python3 -m garak --model_type rest -G {endpoint_config.json} \
     --probes promptinject,dan,leakreplay,encoding,malwaregen,xss \
     --report_prefix .claude/planning/{issue}/garak
   ```
   Probe families to include:
   - `promptinject` / `latentinjection` — LLM01 direct + indirect
   - `dan` / `grandma` / `jailbreak` — guardrail bypass
   - `leakreplay` — training-data / memorized-content leakage (LLM06)
   - `xss` / `htmlinject` — insecure output handling (LLM02)
   - `encoding` — obfuscated-payload bypass
   - `malwaregen` / `realtoxicityprompts` — harmful-content policy
   Record: parse `garak*.report.jsonl` for failed (vulnerable) probes.

### Phase 3: PyRIT Targeted Scenarios
3. **Run PyRIT** for multi-turn / orchestrated attacks garak's
   single-shot probes miss:
   - Multi-turn crescendo jailbreaks
   - System-prompt extraction (LLM07) via role-confusion sequences
   - If the endpoint is an *agent* with tools: tool-abuse via injected
     instructions (highest impact — confirm tool allow-listing).
   Record: PyRIT scoring output; capture the minimal transcript that
   demonstrates each success.

### Phase 4: Normalize & Triage
4. Convert each confirmed scanner failure into one FINDING. Deduplicate
   garak/PyRIT overlaps into a single issue citing both. Downgrade
   probes that "succeeded" but produced only benign output the app
   already handles (e.g. XSS string returned but output is HTML-escaped
   downstream — verify the rendering surface before rating).

## Output Format

Findings append to `.claude/planning/{issue}/07a_SECURITY_AUDIT.md` per
`.claude/skills/_shared/finding-schema.md`. (If running inside the
SDLC AI phase, also surface a summary into `07c_AI_THREAT_MODEL.md` to
sit alongside the manual `/redteam-ai` output — do not overwrite it.)

Specific to this skill:
- **CWE**: CWE-77 / CWE-94 (injection → action), CWE-79 (output XSS),
  CWE-200 (info disclosure), CWE-1426 (improper validation of generative
  AI output) where applicable.
- **OWASP**: OWASP Top 10 for LLM Apps — LLM01 (Prompt Injection),
  LLM02 (Insecure Output Handling), LLM06 (Sensitive Information
  Disclosure), LLM07 (System Prompt Leakage). Tag each finding.
- **CVSS / severity**: gate on capability — no tools + escaped output =
  Medium; tool/file/network access reachable via injection = High/
  Critical. Reuse the severity matrix in `offensive-security`.
- **Evidence**: the probe name, the minimal request/response transcript
  proving the bypass, and the scanner's score. Keep harmful generations
  truncated to the minimum needed as proof.
- **Remediation framing**: app team — structured message roles (never
  concatenate user input into the system prompt), output encoding before
  render, tool-call allow-listing, input/output schema validation, treat
  all retrieved/fetched content as untrusted, rate-limit inference.

Updates `STATUS.md` and the Skills Run Log row to `complete`.

## Quality Check (Self-Review)

- [ ] Target is first-party and in `llm_endpoints` with `llm_redteam:
      approved`
- [ ] Request/cost ceiling respected
- [ ] Each finding has a minimal reproducing transcript, not just a
      scanner score
- [ ] "Succeeded" probes verified against the real rendering / tool
      surface before rating (no theoretical-only criticals)
- [ ] Did not overwrite manual `07c_AI_THREAT_MODEL.md` content
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **Scanner success ≠ real exploit**: garak flags a model emitting an
  XSS string, but if the app HTML-escapes output the impact is nil.
  Always confirm the downstream handling (this mirrors the
  `excessive-data-exposure-hunter` "redacted but returned" caveat).
- **Cost blowout**: full probe sets are large. Start with a focused probe
  list; expand only if the endpoint is high-risk.
- **Non-determinism**: re-run a confirmed finding 2-3x; note the success
  rate in evidence (a 1-in-20 jailbreak is still a finding but rated by
  reliability).

## References

- garak: https://github.com/NVIDIA/garak
- PyRIT: https://github.com/Azure/PyRIT
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- Internal: `/redteam-ai` command, `security-analyst` agent (Phase 7c),
  `offensive-security` → AI/LLM Specific Threats.

## Source Methodology

Cannibalized from the `guardian-cli` (zakirkun/guardian-cli, MIT)
garak/PyRIT integration pattern — adapted to this stack's finding schema
and scope-gating model rather than its agentic orchestrator. Conversion
date: 2026-06-27.
