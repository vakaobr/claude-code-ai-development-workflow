#!/usr/bin/env bash
# Validates the structural correctness of all security skills.
# Does NOT validate methodology accuracy — that's a human job.

set -uo pipefail

SKILLS_DIR=".claude/skills"
PROFILES_FILE=".claude/skills/_shared/tool-profiles.md"
SCOPE_FILE=".claude/security-scope.yaml"
ERRORS=0
WARNINGS=0

# Skills we're checking (excludes _shared and pre-existing framework skills
# that predate the security-skill batch — they use a different template)
EXCLUDE_RE='^(_shared|implementing-code|planning-solutions|reviewing-code|review-fix|researching-code|visual-explainer|offensive-security)$'
mapfile -t SKILLS < <(find "$SKILLS_DIR" -maxdepth 1 -mindepth 1 \
    -type d -exec basename {} \; | grep -vE "$EXCLUDE_RE")

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
