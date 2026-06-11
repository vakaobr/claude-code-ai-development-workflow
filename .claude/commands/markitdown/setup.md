---
name: markitdown/setup
description: Interactive setup wizard for MarkItDown MCP integration. Detects the Python runner, installs markitdown, and registers a local STDIO MCP server for token-saving document conversion.
model: sonnet
---

# MarkItDown MCP Setup Wizard

You are guiding the user through setting up the **MarkItDown MCP** integration, which converts non-plaintext documents (PDF, DOCX, PPTX, XLSX, images, audio, HTML, EPub, ZIP) into clean Markdown. This saves tokens versus the built-in `Read` tool, which renders PDF pages as images.

## Overview

MarkItDown MCP exposes a single tool, `convert_to_markdown(uri)`, accepting `file:`, `http:`, `https:`, and `data:` URIs. We run it as a **local STDIO server installed directly** (not Docker) — Docker cannot read local repository files without volume mounts, which is fatal for a codebase tool (ADR-001). The server is launched through `.claude/scripts/markitdown-mcp-wrapper.sh`, which resolves a Python runner automatically (ADR-002).

## Step 1: Check Existing Configuration

```bash
cat .claude/settings.json
```

If `markitdown` already exists in `mcpServers`, inform the user:

> MarkItDown MCP is already configured in this project. Run `/markitdown/setup` again to reconfigure, or use `/markitdown` to start converting documents.

If not configured, proceed to Step 2.

## Step 2: Verify Python and Detect a Runner

MarkItDown requires **Python ≥ 3.10**. Probe the environment:

```bash
python3 --version
command -v uvx && echo "uvx: available"
command -v pipx && echo "pipx: available"
command -v pip3 && echo "pip3: available"
```

**Decision (matches the wrapper's runner ladder — ADR-002):**

> **Pin the version (Security R3 / 07a A06).** The commands below pin `markitdown-mcp==0.0.1a4` (latest verified at authoring; it is an alpha release). Re-pin to the newest verified version on upgrade, and run `pip-audit` after install to scan the (large) transitive tree.

1. **`uvx` available** → no install needed: `uvx --from "markitdown-mcp==0.0.1a4" markitdown-mcp` runs on demand.
2. **`pipx` available** → no persistent install needed: `pipx run --spec "markitdown-mcp==0.0.1a4" markitdown-mcp` runs on demand.
3. **Only `pip3`** → create a project-local venv and install there (keeps it isolated from the pyenv global environment):
   ```bash
   python3 -m venv .claude/.venvs/markitdown
   .claude/.venvs/markitdown/bin/pip install --upgrade pip
   .claude/.venvs/markitdown/bin/pip install "markitdown-mcp==0.0.1a4"
   .claude/.venvs/markitdown/bin/pip install pip-audit && .claude/.venvs/markitdown/bin/pip-audit || true   # scan deps
   ```

**Python version range — IMPORTANT (verified 2026-06-11):** require **3.10 ≤ Python ≤ 3.13**. If `python3 --version` is **< 3.10**, STOP and select a ≥3.10 interpreter. If it is **≥ 3.14**, the install will **fail** — `markitdown[all]` pulls `youtube-transcript-api~=1.0.0`, which has no distribution for 3.14 (`ResolutionImpossible`). Build the venv with a 3.12/3.13 interpreter instead, e.g.:
```bash
# use an explicit 3.12 interpreter for the venv even if `python3` is newer
~/.pyenv/versions/3.12.9/bin/python3 -m venv .claude/.venvs/markitdown
# (or: pyenv install 3.12 && pyenv local 3.12)
```

## Step 3: Format Support (extras)

**No choice needed — and no API keys needed.** `markitdown-mcp` declares `markitdown[all]` as a hard dependency, so installing it (via any runner above) automatically pulls full format support: PDF, Word, PowerPoint, Excel, images (OCR), audio (transcription), HTML, CSV/JSON/XML, EPub, ZIP, etc. There is no lighter profile while the MCP server is installed — `pip`/`uvx`/`pipx` all resolve `markitdown[all]` regardless. The dependency tree is larger but installs once.

> The default install is fully local and offline. The optional `[az-doc-intel]` / LLM-captioning backends require credentials — out of scope here. If ever added, store keys as environment variables, never in committed files.

## Step 4: Apply Configuration

Add the `markitdown` server to `.claude/settings.json` `mcpServers`, launched via the wrapper script (single source of launch truth):

```json
{
  "mcpServers": {
    "markitdown": {
      "command": "bash",
      "args": ["${workspaceFolder}/.claude/scripts/markitdown-mcp-wrapper.sh"]
    }
  }
}
```

**Do NOT add `mcp__markitdown__convert_to_markdown` to `permissions.allow`.** (Security R2 / 07a H-1.) The tool reads arbitrary `file:` paths; pre-authorizing it would let an indirect prompt injection trigger `convert_to_markdown("file:///…/credentials.json")` with no human prompt. Leaving it unauthorized means each `convert_to_markdown` call asks once — a deliberate human-in-the-loop gate. The frictionless automatic path (the `PreToolUse` Read interceptor, `.claude/hooks/markitdown-read.sh`) does **not** use the MCP tool — it runs the `markitdown` CLI and redirects to a plain `.md` `Read` — so it is unaffected by this and stays prompt-free.

**Preserve all existing `mcpServers` and `permissions.allow` entries** — this is an additive merge to `mcpServers` only, not a replacement. Confirm `.claude/scripts/markitdown-mcp-wrapper.sh` exists and is executable (`ls -l`); if missing, the integration was not fully installed.

## Step 5: Offer the Auto-Conversion Interceptor (ask first)

The MCP server above powers the `/markitdown` command and the `/discover`+`/research` phase hooks. Separately, an optional **user-level `PreToolUse(Read)` interceptor** makes conversion automatic in **every** project: whenever Claude reads a document (`.pdf .docx .doc .pptx .ppt .xlsx .xls .epub`), it is converted to a sibling `.converted.md` *before* the binary loads — no tokens spent on it.

Because this modifies the user's **global** config (`~/.claude/settings.json`, `~/.claude/hooks/`, `~/.claude/.venvs/`), **ASK the user before installing it** — do not install silently:

> ### Enable the auto-conversion interceptor?
>
> This installs a user-level hook so **any** Claude Code session auto-converts documents (PDF/DOCX/PPTX/XLSX/EPub) to Markdown when read — saving tokens everywhere, not just this project. It adds:
> - a Python venv at `~/.claude/.venvs/markitdown`
> - the hook script at `~/.claude/hooks/markitdown-read.sh`
> - a `PreToolUse(Read)` entry in `~/.claude/settings.json`
>
> Note: it catches reads Claude makes; files you *drag-drop* are attached by Claude Code before any hook runs, so use `/markitdown convert <path>` for those.
>
> Install it now? (yes / no)

**If yes**, run the reproducible installer (idempotent — safe even if partly installed):

```bash
bash .claude/scripts/install-markitdown-interceptor.sh
```

It auto-selects a compatible Python (3.10–3.13), creates the venv, copies the hook, and registers it. Report its output to the user.

**If no**, skip — the MCP server + phase hooks still work; the user can run the installer later.

## Step 6: Verify Setup

1. Tell the user to **restart Claude Code** so the MCP server loads.
2. After restart, verify with a sample conversion.

> ### Setup Complete!
>
> MarkItDown MCP has been configured in `.claude/settings.json`.
>
> **Next steps:**
> 1. Restart Claude Code for the MCP server to load
> 2. Run `/markitdown test <path-to-a-pdf>` to verify a real conversion
>
> **Available tool (after restart):**
> - `convert_to_markdown(uri)` — convert a `file:`/`http(s):`/`data:` document to Markdown
>
> **Automatic use:** `/discover` and `/research` convert non-plaintext documents before reading them. If you enabled the interceptor (Step 5), Claude auto-converts documents on **any** `Read`, in every project. After restart, run `/hooks` to confirm `PreToolUse → Read`. Use `/markitdown` directly for one-off conversions or for dragged-in files.

## Error Handling

- **Python < 3.10**: refuse to install; instruct the user to select a ≥3.10 interpreter (pyenv).
- **No runner (no uvx/pipx/pip3)**: install Python 3.10+ (which provides pip), or install `uv`/`pipx`.
- **`ResolutionImpossible` / `youtube-transcript-api` has no matching distribution**: your Python is too new (≥3.14). Rebuild the venv with a 3.12 or 3.13 interpreter (see Step 2).
- **`pip-audit` flags CVEs in `mcp` (1.8.x)**: these are **HTTP/SSE-transport DoS** issues (CVE-2025-53365/53366/66416). This server runs **STDIO-only with no network exposure**, so they are not reachable — **accepted risk**. Do **not** force-upgrade `mcp` past `~=1.8.0`: `markitdown-mcp` pins it, and overriding breaks the declared constraint. Re-evaluate when `markitdown-mcp` (alpha) bumps its `mcp` pin.
- **`pip install` fails on another transitive dependency**: upgrade `pip` (`pip install --upgrade pip`) and retry; if one optional parser fails to build, report which and continue (most formats will still work).
- **Server doesn't appear after restart**: run `bash .claude/scripts/markitdown-mcp-wrapper.sh` manually — it prints to stderr which runner it resolved (or that none was found).
- **Docker caveat**: do NOT switch to the Docker image to "simplify" — it cannot read local `file:` URIs without `-v host:/workdir` volume mounts and path rewriting (ADR-001).
