---
name: retrieval/setup
description: Interactive setup wizard for semantic code retrieval via claude-context MCP. Configures Ollama + Milvus (local) or Zilliz Cloud for codebase indexing and search.
model: sonnet
---

# Semantic Code Retrieval Setup Wizard

You are guiding the user through setting up the **claude-context MCP** integration, which gives Claude Code semantic code search capabilities — hybrid BM25 + vector search over an AST-indexed codebase.

## Overview

claude-context MCP provides:
- **Index** — Parse your codebase with Tree-sitter AST, generate embeddings, store in a vector database
- **Search** — Hybrid keyword (BM25) + semantic (vector) search over code chunks
- **Incremental updates** — Merkle tree change detection re-indexes only modified files

## Step 1: Check Existing Configuration

First, check if claude-context is already registered as an MCP server:

```bash
claude mcp get claude-context
```

If the command returns server details (not "No MCP server found"), inform the user:

> claude-context MCP is already configured. Run `/retrieval/setup` again to reconfigure, or use `/retrieval` to search and index.

If not configured, proceed to Step 2.

> **Note:** Claude Code reads MCP server configuration from `~/.claude.json` (user scope) or a project-local `.mcp.json` (project scope) — **not** from `settings.json`. The `claude mcp` CLI writes to the correct location automatically. Don't hand-edit `mcpServers` blocks into `settings.json` — they will be silently ignored.

## Step 2: Ask About Setup Preference

Present these options clearly and **wait for the user's response**:

> ### Semantic Code Retrieval Setup
>
> **How would you like to run semantic retrieval?**
>
> 1. **Fully local** (recommended) — Ollama for embeddings + Docker Milvus for vector storage. No cloud services, no API keys. Requires Docker and Ollama installed.
> 2. **Zilliz Cloud + Ollama** — Local embeddings via Ollama, cloud-managed vector storage via Zilliz Cloud. Requires Ollama + Zilliz Cloud account.
> 3. **Zilliz Cloud + OpenAI** — Cloud embeddings + cloud storage. Easiest setup, but requires API keys and internet. No local infrastructure needed.
> 4. **OpenAI-compatible local** — LM Studio or similar local inference server + Docker Milvus. For users who prefer a different local embedding runtime.
>
> Which option? (1-4)

## Step 3: Collect Configuration Details

### Option 1: Fully Local (Ollama + Docker Milvus)

Guide the user through prerequisites:

> **Local Setup Prerequisites**
>
> **1. Ollama** (embedding model runtime)
> ```bash
> # Install Ollama if not already installed
> # macOS: brew install ollama
> # Linux: curl -fsSL https://ollama.com/install.sh | sh
>
> # Start Ollama and pull the embedding model
> ollama serve   # if not already running
> ollama pull nomic-embed-text
> ```
>
> **2. Milvus** (vector database)
>
> Milvus standalone needs **etcd** (metadata) and **MinIO** (object storage). Run all three on a user-defined Docker network so they resolve each other by name (default-bridge IPs shuffle on Docker Desktop restarts and break Milvus's etcd connection):
>
> ```bash
> # 1. User-defined network
> docker network create milvus-net
>
> # 2. etcd
> docker run -d --name milvus-etcd --network milvus-net \
>   -p 127.0.0.1:2379:2379 \
>   -e ALLOW_NONE_AUTHENTICATION=yes \
>   quay.io/coreos/etcd:v3.5.18 \
>   etcd --advertise-client-urls=http://0.0.0.0:2379 \
>        --listen-client-urls=http://0.0.0.0:2379 \
>        --auto-compaction-mode=revision --auto-compaction-retention=1000
>
> # 3. MinIO
> docker run -d --name milvus-minio --network milvus-net \
>   -p 127.0.0.1:9000:9000 -p 127.0.0.1:9001:9001 \
>   -e MINIO_ACCESS_KEY=minioadmin -e MINIO_SECRET_KEY=minioadmin \
>   minio/minio:latest server /data --console-address ":9001"
>
> # 4. Milvus (pin a tested version — :latest has shipped breaking changes)
> docker run -d --name milvus --network milvus-net \
>   -p 127.0.0.1:19530:19530 -p 127.0.0.1:9091:9091 \
>   -v milvus-data:/var/lib/milvus \
>   -e ETCD_ENDPOINTS=milvus-etcd:2379 \
>   -e MINIO_ADDRESS=milvus-minio:9000 \
>   -e MINIO_ACCESS_KEY_ID=minioadmin \
>   -e MINIO_SECRET_ACCESS_KEY=minioadmin \
>   milvusdb/milvus:v2.6.15 milvus run standalone
> ```
>
> Confirm everything is running:
> - Ollama: `ollama list` should show `nomic-embed-text`
> - Milvus stack: `docker ps --filter network=milvus-net` should show all three containers
> - Milvus health: `curl -sf http://127.0.0.1:9091/healthz && echo OK`

### Option 2: Zilliz Cloud + Ollama

> **Zilliz Cloud + Ollama Setup**
>
> **1. Ollama** (same as Option 1 above)
>
> **2. Zilliz Cloud** — Sign up at [cloud.zilliz.com](https://cloud.zilliz.com):
>    - Create a free cluster
>    - Note your **Public Endpoint** (e.g., `https://xxx.api.gcp-us-west1.zillizcloud.com`)
>    - Create an **API Key**
>
> Please provide:
> 1. **Zilliz Cloud Endpoint** — Your cluster's public endpoint
> 2. **Zilliz Cloud API Key** — Your cluster's API key
>
> **IMPORTANT**: Store the API key as environment variable `MILVUS_TOKEN`, not directly in settings.json.

### Option 3: Zilliz Cloud + OpenAI

> **Zilliz Cloud + OpenAI Setup**
>
> Please provide:
> 1. **OpenAI API Key** — From [platform.openai.com](https://platform.openai.com)
> 2. **Zilliz Cloud Endpoint** — Your cluster's public endpoint
> 3. **Zilliz Cloud API Key** — Your cluster's API key
>
> **IMPORTANT**: Store API keys as environment variables (`OPENAI_API_KEY`, `MILVUS_TOKEN`), not directly in settings.json.

### Option 4: OpenAI-Compatible Local

> **Local Inference Server + Docker Milvus**
>
> This works with LM Studio, LocalAI, or any OpenAI-compatible API.
>
> **1. Start your local inference server** with an embedding model loaded
> **2. Milvus** (same Docker setup as Option 1)
>
> Please provide:
> 1. **API Base URL** — e.g., `http://localhost:1234/v1`
> 2. **Model name** — The embedding model name in your server

## Step 4: Register the MCP Server

Use `claude mcp add-json` to register the server. Pick the scope:

- **`--scope user`** (recommended for local infrastructure setups) — registered in `~/.claude.json`, available to every project on this machine.
- **`--scope project`** — registered in a project-local `.mcp.json` (commit-friendly if you want teammates to pick it up).

Pre-warm the npm cache once so the first MCP spawn doesn't time out:

```bash
npx -y @zilliz/claude-context-mcp@latest --help </dev/null
```

Then run the command for the chosen option below.

### Option 1: Fully Local

```bash
claude mcp add-json --scope user claude-context '{
  "type": "stdio",
  "command": "npx",
  "args": ["-y", "@zilliz/claude-context-mcp@latest"],
  "env": {
    "EMBEDDING_PROVIDER": "Ollama",
    "EMBEDDING_MODEL": "nomic-embed-text",
    "EMBEDDING_DIMENSION": "768",
    "EMBEDDING_BATCH_SIZE": "5",
    "OLLAMA_HOST": "http://127.0.0.1:11434",
    "OLLAMA_NUM_PARALLEL": "1",
    "MILVUS_ADDRESS": "127.0.0.1:19530",
    "SPLITTER_TYPE": "ast",
    "HYBRID_MODE": "true",
    "CUSTOM_IGNORE_PATTERNS": "node_modules/**,.git/**,vendor/**,dist/**,build/**,.next/**,__pycache__/**,*.pyc,.terraform/**"
  }
}'
```

### Option 2: Zilliz Cloud + Ollama

Replace `<user-provided-zilliz-endpoint>` and export `MILVUS_TOKEN` in your shell **before** running the command (so the secret never lands in `~/.claude.json`):

```bash
export MILVUS_TOKEN='your-zilliz-cloud-api-key'

claude mcp add-json --scope user claude-context "$(cat <<JSON
{
  "type": "stdio",
  "command": "npx",
  "args": ["-y", "@zilliz/claude-context-mcp@latest"],
  "env": {
    "EMBEDDING_PROVIDER": "Ollama",
    "EMBEDDING_MODEL": "nomic-embed-text",
    "EMBEDDING_DIMENSION": "768",
    "EMBEDDING_BATCH_SIZE": "5",
    "OLLAMA_HOST": "http://127.0.0.1:11434",
    "OLLAMA_NUM_PARALLEL": "1",
    "MILVUS_ADDRESS": "<user-provided-zilliz-endpoint>",
    "MILVUS_TOKEN": "${MILVUS_TOKEN}",
    "SPLITTER_TYPE": "ast",
    "HYBRID_MODE": "true",
    "CUSTOM_IGNORE_PATTERNS": "node_modules/**,.git/**,vendor/**,dist/**,build/**,.next/**,__pycache__/**,*.pyc,.terraform/**"
  }
}
JSON
)"
```

### Option 3: Zilliz Cloud + OpenAI

Export both secrets before running:

```bash
export OPENAI_API_KEY='sk-...'
export MILVUS_TOKEN='your-zilliz-cloud-api-key'

claude mcp add-json --scope user claude-context "$(cat <<JSON
{
  "type": "stdio",
  "command": "npx",
  "args": ["-y", "@zilliz/claude-context-mcp@latest"],
  "env": {
    "OPENAI_API_KEY": "${OPENAI_API_KEY}",
    "MILVUS_ADDRESS": "<user-provided-zilliz-endpoint>",
    "MILVUS_TOKEN": "${MILVUS_TOKEN}",
    "SPLITTER_TYPE": "ast",
    "HYBRID_MODE": "true",
    "CUSTOM_IGNORE_PATTERNS": "node_modules/**,.git/**,vendor/**,dist/**,build/**,.next/**,__pycache__/**,*.pyc,.terraform/**"
  }
}
JSON
)"
```

### Option 4: OpenAI-Compatible Local

```bash
claude mcp add-json --scope user claude-context '{
  "type": "stdio",
  "command": "npx",
  "args": ["-y", "@zilliz/claude-context-mcp@latest"],
  "env": {
    "EMBEDDING_PROVIDER": "OpenAI",
    "OPENAI_API_KEY": "local",
    "OPENAI_BASE_URL": "<user-provided-base-url>",
    "EMBEDDING_MODEL": "<user-provided-model-name>",
    "MILVUS_ADDRESS": "127.0.0.1:19530",
    "SPLITTER_TYPE": "ast",
    "HYBRID_MODE": "true",
    "CUSTOM_IGNORE_PATTERNS": "node_modules/**,.git/**,vendor/**,dist/**,build/**,.next/**,__pycache__/**,*.pyc,.terraform/**"
  }
}'
```

## Step 5: Verify Setup

Verify the registration and connection from the shell — no Claude Code restart needed for the new server to be picked up by future sessions:

```bash
claude mcp list | grep claude-context
```

Expected: `claude-context: ... - ✓ Connected`

If it shows `✗ Failed to connect`, check `claude --mcp-debug` startup output for the underlying error (most common: Milvus / Ollama not running, or an `EMBEDDING_DIMENSION` mismatch).

> ### Setup Complete!
>
> claude-context MCP is registered. New Claude Code sessions will load it automatically.
>
> **Next steps:**
> 1. Open a new Claude Code session in this project
> 2. Run `/retrieval index` to build the search index
> 3. Run `/retrieval search "your query"` to test semantic search
>
> **Available tools (after the next session starts):**
> - `search_code` — Hybrid BM25 + semantic search over indexed code
> - `index_codebase` — Build or update the code index (AST + embeddings)
> - `get_indexing_status` — Check index health and progress
> - `clear_index` — Remove the index for a codebase
>
> **Usage:** Run `/retrieval [request]` to search, index, or manage. The `/research` and `/implement` skills will also use retrieval automatically when available.

## Error Handling

- If `npx` is not available: suggest installing Node.js 20+ (`node --version` must be >= 20.0.0)
- If Docker is not available for Milvus: suggest installing Docker Desktop or using Zilliz Cloud (Option 2/3)
- If Ollama is not installed: suggest installing via `brew install ollama` (macOS) or `curl -fsSL https://ollama.com/install.sh | sh` (Linux)
- If `nomic-embed-text` not pulled: run `ollama pull nomic-embed-text`
- If Milvus container not running: `docker start milvus`
- If Ollama not running: `ollama serve`
- If embedding dimension errors occur: ensure `EMBEDDING_DIMENSION=768` is set (workaround for Ollama batch issue)
