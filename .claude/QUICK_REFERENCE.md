# Quick Reference Commands

## Terraform
```bash
terraform fmt -recursive          # Format all .tf files
terraform validate                # Validate configuration
terraform plan -out=tfplan        # Create execution plan
terraform apply tfplan            # Apply changes
```

## Docker
```bash
docker ps                         # List running containers
docker images                     # List images
docker system prune               # Clean up unused resources
```

## Kubernetes / OpenShift
```bash
kubectl get pods -A               # All pods across namespaces
kubectl describe pod {name}       # Pod details and events
kubectl logs {pod} -f             # Stream logs
kubectl apply --dry-run=client -f manifest.yaml  # Validate before apply
oc get routes                     # OpenShift routes
oc adm policy who-can get pods    # RBAC check
```

## Ansible
```bash
ansible-playbook site.yml --check --diff   # Dry-run with diff
ansible-lint playbook.yml                   # Lint playbook
ansible-vault encrypt secrets.yml           # Encrypt secrets file
ansible-inventory --graph                   # Show inventory tree
```

## SDLC Workflow
```bash
cat .claude/planning/{issue-name}/00_STATUS.md   # Check workflow status

/discover [description]              # Phase 1: Scope + stack detection + repo map
/repo-map [path]                     # Generate compact repo structural overview (standalone)
/research {issue-name}               # Phase 2: Codebase analysis
/design-system {issue-name}          # Phase 3: Architecture + ADRs
/plan {issue-name}                   # Phase 4: Implementation plan
/implement {issue-name}              # Phase 5: Code + tests
/review {issue-name}                 # Phase 6: Code review
/security {issue-name}               # Phase 7a: Static security audit
/security/pentest {issue-name}       # Phase 7b: Dynamic pentest (Shannon)
/security/redteam-ai {issue-name}    # Phase 7c: AI model audit (if LLMs)
/security/harden {issue-name}        # Phase 8: Fix confirmed vulnerabilities
/deploy-plan {issue-name}            # Phase 9: Deployment strategy
/observe {issue-name}                # Phase 10: Observability
/retro {issue-name}                  # Phase 11: Retrospective
```

## Integrations (MCP)
```bash
/retrieval/setup ; /retrieval search "..."   # Semantic code search (claude-context)
/firecrawl/setup ; /firecrawl scrape <url>    # Web scraping (Firecrawl)
/markitdown/setup ; /markitdown <file|url>    # PDF/DOCX/XLSX → Markdown (MarkItDown) — auto-runs in /discover + /research
/n8n/setup ; /n8n <request>                   # Workflow automation (n8n)
```

## All Available Commands
Run `/COMMAND_USAGE` for the full command catalog with descriptions.
