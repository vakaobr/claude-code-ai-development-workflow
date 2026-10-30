#!/usr/bin/env python3
"""Vendor a pinned, reviewed copy of the Elephant-Goldfish Model (EGM).

EGM (https://github.com/google/elephant-goldfish-model, Apache-2.0) is a set of
design-drafting skills and zero-context ("Goldfish") reviewer personas. The
/sdlc workflow uses its reviewers for the Phase 3b design review, and its
interactive skills are available as slash commands.

It is vendored at a commit instead of installed as a plugin so that upstream
prompt changes only reach sessions through a reviewed re-sync. To upgrade:
read the upstream diff between the pinned commit and the new one, then run

    python3 ~/.claude/scripts/sync-egm.py --ref <commit-sha>

What it writes under the target root (default ~/.claude):
- vendor/egm/        upstream files, unmodified (the "plugin root"), plus NOTICE.md
- agents/egm-*.md    EGM's Claude Code reviewer adapters, root path rewritten
- skills/egm-*/      the selected skills, root paths rewritten and a header added

Nothing outside those paths is touched.
"""

from __future__ import annotations

import argparse
import datetime
import io
import pathlib
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request

REPO = "google/elephant-goldfish-model"
UPSTREAM_PATHS = ["agents", "resources", "docs", "skills", "LICENSE", "README.md", "TESTING.md"]
DOCS_KEEP = {"claude.md", "harnesses.md", "getting_started.md", "codex.md", "privacy.md"}
SKILLS = ["egm-review", "egm-review-loop", "egm-brainstorm", "egm-draft", "egm-resolve", "egm-bootstrap"]
ROOT_REF = "<EGM root>"
ROOT_RULE = (
    "`<EGM root>` is `.claude/vendor/egm` in the current project if that folder exists "
    "(project install), otherwise `~/.claude/vendor/egm` (user install)."
)
MARKER = "Vendored EGM root (managed by scripts/sync-egm.py)"


def fetch(ref: str, workdir: pathlib.Path) -> pathlib.Path:
    url = f"https://codeload.github.com/{REPO}/tar.gz/{ref}"
    with urllib.request.urlopen(url, timeout=60) as resp:
        data = resp.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        tar.extractall(workdir, filter="data")
    (top,) = [p for p in workdir.iterdir() if p.is_dir()]
    return top


def rewrite(text: str) -> str:
    text = text.replace("${CLAUDE_PLUGIN_ROOT}", ROOT_REF)
    text = re.sub(r"\.\./\.\./", ROOT_REF + "/", text)
    # Registered here without the plugin namespace: egm:egm-design -> egm-design.
    return re.sub(r"\begm:(egm-[a-z-]+)", r"\1", text)


def skill_header(ref: str) -> str:
    return (
        f"> Vendored from EGM `{ref[:12]}` (Apache-2.0, see `{ROOT_REF}/NOTICE.md`). "
        f"{ROOT_RULE} Resolve `agents/`, `resources/` and `docs/` paths "
        f"in this skill against it, and this skill's own `references/` against this folder. "
        "Reviewer agent types are registered without the `egm:` prefix "
        "(for example `egm-zoom-out`).\n\n"
    )


def add_header(skill_md: str, ref: str) -> str:
    match = re.match(r"(?s)(---\n.*?\n---\n)(.*)", skill_md)
    if not match:
        sys.exit("SKILL.md without frontmatter: refusing to guess where the header goes")
    return match.group(1) + "\n" + skill_header(ref) + match.group(2).lstrip("\n")


def safe_replace_dir(target: pathlib.Path, expected_marker: pathlib.Path | None) -> None:
    """Remove a previously generated dir, but only one this script created."""
    if not target.exists():
        return
    if expected_marker is not None and not expected_marker.exists():
        sys.exit(f"{target} exists but was not created by this script ({expected_marker.name} missing); not touching it")
    shutil.rmtree(target)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ref", required=True, help="full or short upstream commit SHA (a reviewed commit, not a branch)")
    parser.add_argument("--root", default=str(pathlib.Path.home() / ".claude"), help="target root (default ~/.claude)")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{7,40}", args.ref):
        sys.exit("--ref must be a commit SHA, so the vendored copy is pinned")

    root = pathlib.Path(args.root).expanduser().resolve()
    vendor = root / "vendor" / "egm"

    with tempfile.TemporaryDirectory() as tmp:
        src = fetch(args.ref, pathlib.Path(tmp))
        plugin_json = (src / ".claude-plugin" / "plugin.json").read_text()
        version = re.search(r'"version":\s*"([^"]+)"', plugin_json).group(1)

        safe_replace_dir(vendor, vendor / "NOTICE.md")
        vendor.mkdir(parents=True)
        for name in UPSTREAM_PATHS:
            s = src / name
            if s.is_dir():
                ignore = None
                if name == "docs":
                    ignore = lambda d, files: [f for f in files if pathlib.Path(d) == s and f not in DOCS_KEEP]  # noqa: E731
                shutil.copytree(s, vendor / name, ignore=ignore)
            else:
                shutil.copy2(s, vendor / name)

        generated_agents = []
        for adapter in sorted((src / ".claude-plugin" / "agents").glob("*.md")):
            text = rewrite(adapter.read_text())
            text = re.sub(r"(?s)(\n---\n)", r"\1\n" + ROOT_RULE + "\n", text, count=1)
            name = re.search(r"(?m)^name:\s*(\S+)", text).group(1)
            out = root / "agents" / f"{name}.md"
            existing = out.read_text() if out.exists() else ""
            if existing and "vendor/egm" not in existing and ROOT_REF not in existing:
                sys.exit(f"{out} exists and is not an EGM adapter; not overwriting")
            out.write_text(text)
            generated_agents.append(out.name)

        generated_skills = []
        for skill in SKILLS:
            out_dir = root / "skills" / skill
            safe_replace_dir(out_dir, out_dir / ".egm-vendored")
            shutil.copytree(src / "skills" / skill, out_dir)
            for md in out_dir.rglob("*.md"):
                md.write_text(rewrite(md.read_text()))
            skill_md = out_dir / "SKILL.md"
            skill_md.write_text(add_header(skill_md.read_text(), args.ref))
            (out_dir / ".egm-vendored").write_text(args.ref + "\n")
            generated_skills.append(skill)

    leftovers = [
        str(p) for p in [*(root / "agents").glob("egm-*.md"), *(root / "skills").glob("egm-*/**/*.md")]
        if "${CLAUDE_PLUGIN_ROOT}" in p.read_text()
    ]
    if leftovers:
        sys.exit(f"unresolved ${{CLAUDE_PLUGIN_ROOT}} left in: {leftovers}")

    today = datetime.date.today().isoformat()
    (vendor / "NOTICE.md").write_text(
        f"""# {MARKER}

This folder contains files from the Elephant-Goldfish Model (EGM),
https://github.com/{REPO}, Copyright 2026 Google LLC, licensed under the
Apache License 2.0 (see `LICENSE` in this folder). EGM is not an officially
supported Google product.

- Upstream commit: `{args.ref}` (plugin version {version})
- Vendored on: {today}
- Synced by: `scripts/sync-egm.py --ref {args.ref}`

## Files in this folder

Copied unmodified from upstream: {", ".join(f"`{p}`" for p in UPSTREAM_PATHS)}
(from `docs/`, only {", ".join(sorted(DOCS_KEEP))}).

## Modified copies outside this folder

- `agents/{{{",".join(generated_agents)}}}`: upstream `.claude-plugin/agents/*.md`
  with `${{CLAUDE_PLUGIN_ROOT}}` replaced by `{ROOT_REF}`.
- `skills/{{{",".join(generated_skills)}}}`: upstream `skills/<name>/` with
  `${{CLAUDE_PLUGIN_ROOT}}` and `../../` replaced by `{ROOT_REF}`, the `egm:`
  agent namespace removed, and a header in each `SKILL.md` naming this commit.

No reviewer persona, standard or review protocol text was changed.
"""
    )
    print(f"EGM {version} @ {args.ref[:12]} vendored into {vendor}")
    print(f"agents: {', '.join(generated_agents)}")
    print(f"skills: {', '.join(generated_skills)}")


if __name__ == "__main__":
    main()
