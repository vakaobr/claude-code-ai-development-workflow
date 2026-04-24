# Skill Name Mapping

Maps each Portuguese-named NotebookLM note to its English skill name,
tier, default model, and the `allowed-tools` profile it should use.

Load this file when running the batch conversion so every skill gets
the right name and metadata without Claude having to guess.

## Mapping Table

| # | Source Note (Portuguese filename)                                              | Skill Name (kebab-case)         | Category           | Model  | Tools Profile  | Tier |
|---|---------------------------------------------------------------------------------|---------------------------------|--------------------|--------|---------------|------|
| 1 | Guia Completo de Segurança e Testes contra Clickjacking.md                      | clickjacking-hunter             | client-side        | sonnet | passive       | T2   |
| 2 | Guia Completo de Segurança e Testes em Ataques XXE.md                           | xxe-hunter                      | injection          | sonnet | active        | T1   |
| 3 | Guia Completo de Testes e Mitigação de DOM XSS.md                               | dom-xss-hunter                  | client-side        | sonnet | active        | T1   |
| 4 | Guia Completo de Testes e Mitigação de IDOR.md                                  | idor-hunter                     | access-control     | sonnet | active        | T1   |
| 5 | Guia Completo de Testes e Mitigação de SSTI.md                                  | ssti-hunter                     | injection          | opus   | active        | T1   |
| 6 | Guia Compreensivo de Auditoria e Testes de SQL Injection.md                     | sqli-hunter                     | injection          | opus   | active        | T1   |
| 7 | Guia de Auditoria e Segurança em Misconfigurações AWS IAM.md                    | aws-iam-hunter                  | cloud              | opus   | cloud-readonly| T3   |
| 8 | Guia de Exploração e Mitigação de Injeção de Template (SSTI).md                 | ssti-hunter-deep                | injection          | opus   | active        | T1   |
| 9 | Guia de Reconhecimento Ativo em Aplicações Web.md                               | web-recon-active                | recon              | sonnet | active        | T4   |
| 10 | Guia de Reconhecimento e Mapeamento de Superfície de APIs.md                   | api-recon                       | recon              | sonnet | active        | T4   |
| 11 | Guia de Reconhecimento Passivo em Aplicações Web.md                            | web-recon-passive               | recon              | sonnet | passive       | T4   |
| 12 | Guia de Segurança e Auditoria em Pipelines CI_CD GitLab.md                     | gitlab-cicd-hunter              | cicd               | opus   | cicd-readonly | T3   |
| 13 | Guia de Segurança e Gerenciamento de Sessão em Aplicações Web.md               | session-flaw-hunter             | authentication     | sonnet | active        | T1   |
| 14 | Guia de Segurança e Testes Contra Ataques CSRF.md                              | csrf-hunter                     | client-side        | sonnet | active        | T2   |
| 15 | Guia de Segurança e Testes em APIs GraphQL.md                                  | graphql-hunter                  | api                | opus   | active        | T1   |
| 16 | Guia de Segurança e Testes em Vulnerabilidades JWT.md                          | jwt-hunter                      | authentication     | sonnet | active        | T1   |
| 17 | Guia de Segurança_ Escassez de Recursos e Limitação de Taxa.md                 | rate-limit-hunter               | api                | sonnet | active        | T2   |
| 18 | Guia de Segurança_ HPP e Mass Assignment em APIs.md                            | mass-assignment-hunter          | api                | sonnet | active        | T1   |
| 19 | Guia de Testes e Mitigação de Falhas Criptográficas.md                         | crypto-flaw-hunter              | cross-cutting      | opus   | passive       | T2   |
| 20 | Guia de Testes e Mitigação de Falhas de Autenticação.md                        | auth-flaw-hunter                | authentication     | opus   | active        | T1   |
| 21 | Guia de Vulnerabilidades em Lógica de Negócios.md                              | business-logic-hunter           | logic              | opus   | active        | T1   |
| 22 | Guia de Vulnerabilidades em OAuth 2.0 e OpenID Connect.md                      | oauth-oidc-hunter               | authentication     | opus   | active        | T1   |
| 23 | Guia Essencial de Segurança em APIs_ BOLA e BFLA.md                            | bola-bfla-hunter                | access-control     | sonnet | active        | T1   |
| 24 | Guia Estratégico de Injeção de Comandos no Sistema Operacional.md              | command-injection-hunter        | injection          | opus   | active        | T1   |
| 25 | Guia Estratégico de Testes e Mitigação de SSRF.md                              | ssrf-hunter                     | server-side        | opus   | active        | T1   |
| 26 | Guia Mestre de Vulnerabilidades XSS_ Detecção e Mitigação.md                   | xss-hunter                      | client-side        | sonnet | active        | T1   |
| 27 | Guia Metodológico de Segurança em APIs OWASP.md                                | owasp-api-top10-tester          | api                | opus   | active        | T1   |
| 28 | Guia Técnico de Desserialização Insegura e Metodologia de Testes.md            | deserialization-hunter          | injection          | opus   | active        | T2   |
| 29 | Guia Técnico de Exposição Excessiva de Dados em APIs.md                        | excessive-data-exposure-hunter  | api                | sonnet | active        | T2   |
| 30 | Guia Técnico de Redirecionamento Aberto_ Auditoria e Mitigação.md              | open-redirect-hunter            | client-side        | sonnet | active        | T2   |
| 31 | Guia Técnico de Server-Side Template Injection (SSTI).md                       | ssti-hunter-reference           | injection          | opus   | active        | T1   |
| 32 | Guia Técnico de Subdomain Takeover_ Detecção e Mitigação.md                    | subdomain-takeover-hunter       | recon              | sonnet | passive       | T2   |
| 33 | Guia Técnico_ Exploração de SSRF em Metadados de Nuvem.md                      | ssrf-cloud-metadata-hunter      | cloud              | opus   | active        | T1   |
| 34 | Guia Técnico_ Vulnerabilidades de Inclusão de Arquivos e Traversal.md          | path-traversal-hunter           | injection          | sonnet | active        | T2   |
| 35 | Guia Técnico_ Vulnerabilidades e Mitigação de Misconfigurações CORS.md         | cors-misconfig-hunter           | client-side        | sonnet | passive       | T2   |
| 36 | Guia Técnico_ Web Cache Poisoning e HTTP Smuggling.md                          | cache-smuggling-hunter          | server-side        | opus   | active        | T2   |
| 37 | Mapeamento e Auditoria de Fluxos de Autenticação.md                            | auth-flow-mapper                | authentication     | sonnet | passive       | T4   |
| 38 | Metodologia de Reconhecimento e Mapeamento de Superfície de Ataque.md          | attack-surface-mapper           | recon              | sonnet | active        | T4   |
| 39 | Segredos em Código_ Detecção e Resposta a Vazamentos.md                        | secrets-in-code-hunter          | cicd               | sonnet | repo-readonly | T3   |
| 40 | Segurança e Auditoria de Buckets Amazon S3.md                                  | s3-misconfig-hunter             | cloud              | sonnet | cloud-readonly| T3   |
| 41 | Segurança e Testes em Ambientes de Containers e Imagens.md                     | container-hunter                | cloud              | sonnet | cloud-readonly| T3   |

## Notes on Overlaps

Rows 5, 8, and 31 are all SSTI. Recommend merging into one skill
(`ssti-hunter`) during conversion; the batch prompt handles this.

Rows 9, 11, 38 are all recon. `web-recon-passive` and `web-recon-active`
stay separate (different tool profiles). `attack-surface-mapper` merges
into them as a "Phase 1: inventory" section.

Rows 33 and 25 are both SSRF. Keep `ssrf-hunter` as the main skill and
`ssrf-cloud-metadata-hunter` as a specialist for the IMDS/cloud metadata
variant — the techniques and payloads are distinct enough to warrant it.

## Tools Profiles

Defined in `.claude/skills/_shared/tool-profiles.md`. Summary:

- **passive**: Read, Grep, Glob, WebFetch (no Bash, no Write outside
  planning/)
- **active**: passive + Bash with allowlist (curl, httpx, ffuf, nuclei,
  gobuster, arjun, gf, jq, nmap --script=safe scripts only)
- **cloud-readonly**: passive + Bash with aws CLI restricted to
  describe-*, get-*, list-* verbs (no create, update, delete, put)
- **cicd-readonly**: passive + Bash with glab/gitlab-cli restricted to
  read operations
- **repo-readonly**: passive + Bash with git log/show/grep/blame only
