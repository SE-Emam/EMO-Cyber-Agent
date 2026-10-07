# POST-T020 G0 Gap Matrix (condensed from G0-B sweep)

Sweep: rg excluding .git/.venv/__pycache__. True code TODO/FIXME debt: 0.
QUARANTINE (47 files) = enforcement, not gaps. `legacy` = intentional shims.

| Domain | Status | Evidence |
|---|---|---|
| Hosts (5 vendors) | CONTRACT-TESTED, Not-tested rows | hosts_*.py honesty headers; compat_matrix 5x Not-tested; generic-mcp Contract-tested |
| anythingllm env | NOT EXECUTED (1 honest skip) | e2e_matrix.py:462; POST-T019:54 |
| HTTP transport | MISSING (config-data only) | mcp/server.py stdio-only; ECA-T013.md:16 deferred; hosts get_http_config placeholders |
| Checklist framework | PARTIAL (data-only) | bootstrap.py data checklist; template unsigned; 19-release-checklist.md markdown |
| Templates (94 files) | IMPLEMENTED, proliferation deferred | POST-RC-011:237; report_templates/spec.py:204 |
| Heuristics | IMPLEMENTED, non-authoritative by design | threat_rules.py:104; sanitizer/firewall regex defense-in-depth |
| Python (3.11-3.14) | TESTED | pyproject classifiers; full suite green |
| Platform | single-OS tested | darwin only; no windows/linux evidence |
| CI | PASS, 1 explicit SKIP | source_tree_independence SKIP |
| Benchmark corpus | 105 files, expansion deferred | POST-RC-013:18; POST-T016:191 |
| E2E | 28 executed + 1 honest skip | e2e_matrix; contract-only vendor paths |
| Security markers | enforced, not gaps | binding/trust/session/lifecycle quarantine paths tested |

Top 5 POST-T020 priorities: (1) HTTP server; (2) vendor behavior interop;
(3) checklist/template enforcement; (4) heuristic measurement (non-authority);
(5) benchmark history + tree-independence SKIP + template distribution.
