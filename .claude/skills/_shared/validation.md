# Post-Batch Validation

Run this against the output after Claude Code finishes all 41 skills.
It catches the three most common failure modes: YAML drift, missing
required sections, and tool-profile widening.

## Manual spot-check (5 minutes)

Pick 4 skills randomly from different categories and read them end to
end. You're looking for:

- [ ] Does the description actually describe what the skill does?
- [ ] Would I invoke this skill based on the description alone?
- [ ] Does the methodology read like instructions, or like an essay?
- [ ] Are remediation snippets concrete code, or generic advice?
- [ ] Does the Authorization Check section match the template verbatim?

If 1-2 of those fail on any skill, tune the batch prompt and re-run
that skill. If 3+ fail, the prompt has a systemic issue — fix it
before accepting any output.

## Automated validation script

Save as `scripts/validate-skills.sh` in your repo, run from repo root.

```bash
#!/usr/bin/env bash
# Validates the structural correctness of all security skills.
# Does NOT validate methodology accuracy — that's a human job.

set -uo pipefail

SKILLS_DIR=".claude/skills"
PROFILES_FILE=".claude/skills/_shared/tool-profiles.md"
SCOPE_FILE=".claude/security-scope.yaml"
ERRORS=0
WARNINGS=0

# Skills we're checking (excludes _shared)
mapfile -t SKILLS < <(find "$SKILLS_DIR" -maxdepth 1 -mindepth 1 \
    -type d ! -name '_shared' -exec basename {} \;)

echo "Validating ${#SKILLS[@]} skills..."

for skill in "${SKILLS[@]}"; do
    file="$SKILLS_DIR/$skill/SKILL.md"
    echo ""
    echo "=== $skill ==="

    # 1. File exists
    if [[ ! -f "$file" ]]; then
        echo "  ERROR: SKILL.md missing"
        ERRORS=$((ERRORS+1))
        continue
    fi

    # 2. Frontmatter parses
    if ! awk '/^---$/{c++; if(c==2)exit} c==1' "$file" \
         | grep -q "^name:"; then
        echo "  ERROR: frontmatter missing or malformed"
        ERRORS=$((ERRORS+1))
        continue
    fi

    # 3. Name matches directory name
    name=$(awk '/^name:/{print $2; exit}' "$file")
    if [[ "$name" != "$skill" ]]; then
        echo "  ERROR: name '$name' != directory '$skill'"
        ERRORS=$((ERRORS+1))
    fi

    # 4. Required frontmatter fields
    for field in description model allowed-tools metadata; do
        if ! grep -q "^$field:" "$file"; then
            echo "  ERROR: missing frontmatter field: $field"
            ERRORS=$((ERRORS+1))
        fi
    done

    # 5. Description length sanity (>50 chars, <1024)
    desc_len=$(awk '/^description:/{
        sub(/^description: *"?/,"");
        sub(/"? *$/,"");
        print length
    }' "$file")
    if [[ "$desc_len" -lt 50 ]]; then
        echo "  WARN: description too short ($desc_len chars)"
        WARNINGS=$((WARNINGS+1))
    fi
    if [[ "$desc_len" -gt 1024 ]]; then
        echo "  ERROR: description exceeds 1024 chars ($desc_len)"
        ERRORS=$((ERRORS+1))
    fi

    # 6. Required body sections
    for section in \
        "^## Goal" \
        "^## When to Use" \
        "^## When NOT to Use" \
        "^## Authorization Check" \
        "^## Methodology" \
        "^## Output Format" \
        "^## Quality Check" \
    ; do
        if ! grep -q "$section" "$file"; then
            echo "  ERROR: missing section: $section"
            ERRORS=$((ERRORS+1))
        fi
    done

    # 7. Mandatory authorization phrase
    if ! grep -qi "security-scope.yaml" "$file"; then
        echo "  ERROR: does not reference security-scope.yaml"
        ERRORS=$((ERRORS+1))
    fi

    # 8. Defensive framing check (heuristic)
    attacker_phrases=$(grep -ciE \
        "attacker (can|could|will|may) (steal|pwn|own|exfiltrate|compromise)" \
        "$file" || true)
    if [[ "$attacker_phrases" -gt 0 ]]; then
        echo "  WARN: $attacker_phrases attacker-voice phrases"
        echo "        (should be rewritten defensively)"
        WARNINGS=$((WARNINGS+1))
    fi

    # 9. Forbidden tools check (the big one)
    forbidden='sqlmap|metasploit|msfconsole|hydra|medusa|hashcat|nikto'
    if grep -qE "Bash\((${forbidden}):" "$file"; then
        matched=$(grep -oE "Bash\((${forbidden}):" "$file" | head -3)
        echo "  ERROR: forbidden tool in allowed-tools: $matched"
        ERRORS=$((ERRORS+1))
    fi

    # 10. aws write-verb check for cloud skills
    if grep -q "cloud-readonly" "$file"; then
        if grep -qE "aws: ?(create|update|delete|put|attach|detach)" \
           "$file"; then
            echo "  ERROR: cloud-readonly skill requests aws write verb"
            ERRORS=$((ERRORS+1))
        fi
    fi

    # 11. References folder consistency
    if grep -q "^## References" "$file"; then
        refs_dir="$SKILLS_DIR/$skill/references"
        grep -oE 'references/[a-z-]+\.md' "$file" | sort -u | \
        while read ref; do
            if [[ ! -f "$SKILLS_DIR/$skill/$ref" ]]; then
                echo "  WARN: referenced file missing: $ref"
            fi
        done
    fi

    echo "  ok"
done

echo ""
echo "===================="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo "===================="

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
```

## Known-pass criteria

The batch succeeded if:
- 0 errors on all 41 skills
- < 10 total warnings across all skills
- Your random 4-skill manual spot-check passes all 5 checks
- `grep -r "TODO\|FIXME\|INVENT\|\[SUPPLEMENTED\]" .claude/skills/`
  returns nothing (means Claude didn't silently flag uncertain areas)

## Triage for failures

| Failure pattern | Cause | Fix |
|---|---|---|
| Same error in many skills | Prompt bug | Fix prompt, re-run batch |
| One skill fails structure | Note was atypical | Re-run that skill with notes about its structure |
| Forbidden tool requested | Profile lookup wrong | Check mapping table, re-run |
| Description mostly generic | Source note was thin | Manually tighten the description — don't blame the prompt |
| attacker-voice warnings | Source note used attacker voice | Single-skill rerun with "enforce defensive voice" reminder |
