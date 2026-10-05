"""Reference local provider — POST-RC-005 initial provider.

Deterministic, dependency-free analysis: stdlib `ast` for Python
(symbols, imports, intra-project calls), line patterns for JS/TS
routes and functions, manifest parsing for dependencies. Declares
ONLY what it truly supports — no dataflow/taint claims. Everything
cross-file is marked incomplete with LOW/MEDIUM confidence. Source
text is DATA: parsed, never executed.
"""

from __future__ import annotations

import ast as _ast
import json as _json
import re as _re
from typing import Any

from emo_cyber_agent.code_intelligence.provider import CodeIntelligenceProvider
from emo_cyber_agent.code_intelligence.spec import detect_language

_MAX_FILE_BYTES = 200_000

_ROUTE_PATTERNS: tuple[tuple[str, _re.Pattern[str]], ...] = (
    ("flask", _re.compile(r"""@\w*(?:app|blueprint)\.route\(\s*['"](?P<path>[^'"]+)['"]\s*(?:,\s*methods\s*=\s*\[(?P<methods>[^\]]*)\])?""")),
    ("fastapi", _re.compile(r"""@\w+\.(?P<method>get|post|put|patch|delete)\(\s*['"](?P<path>[^'"]+)['"]""")),
    ("express", _re.compile(r"""(?:app|router)\.(?P<method>get|post|put|patch|delete)\(\s*['"](?P<path>[^'"]+)['"]""")),
)
_FUNC_PATTERN = _re.compile(r"""(?:function\s+(?P<name1>[A-Za-z_$][\w$]*)|(?P<name2>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\()""")
_AUTH_HINT = _re.compile(r"auth|login|require_|_required|check_|verify|guard|policy|role|owner|tenant|rls", _re.IGNORECASE)
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class ReferenceLocalProvider(CodeIntelligenceProvider):
    @property
    def provider_id(self) -> str:
        return "reference-local"

    @property
    def provider_version(self) -> str:
        return "0.1.0"

    def capabilities(self) -> tuple[str, ...]:
        return ("ast", "symbols", "references", "call_graph", "dependencies", "routes", "auth_boundaries")

    def analyze(self, *, snapshot: Any, files: dict[str, str]) -> Any:
        bundle: dict[str, Any] = {"symbols": [], "ast_refs": [], "call_edges": [], "dependency_edges": [], "endpoints": [], "boundaries": [], "skipped": [], "nondeterministic": False}
        defined: dict[str, str] = {}
        for path in sorted(files):
            content = files[path]
            if len(content.encode("utf-8", errors="replace")) > _MAX_FILE_BYTES:
                bundle["skipped"].append(path)
                continue
            language = detect_language(path)
            if language == "python":
                self._python(path, content, bundle, defined)
            elif language in ("javascript", "typescript"):
                self._javascript(path, content, bundle, defined)
            elif path.endswith("requirements.txt"):
                self._requirements(path, content, bundle)
            elif path.endswith("package.json"):
                self._package_json(path, content, bundle)
        self._cross_file_calls(bundle, defined)
        return bundle

    # -- python (stdlib ast) ----------------------------------------------

    def _python(self, path: str, content: str, bundle: dict[str, Any], defined: dict[str, str]) -> None:
        try:
            tree = _ast.parse(content)
        except SyntaxError:
            bundle.setdefault("parse_failures", []).append(path)
            return
        for node in _ast.walk(tree):
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                sid = f"{path}:{node.name}"
                defined.setdefault(node.name, sid)
                bundle["symbols"].append({"symbol_id": sid, "kind": "function", "name": node.name, "file": path, "location": {"path": path, "line": node.lineno, "column": (node.col_offset or 0) + 1, "end_line": node.lineno}, "scope": "module", "exported": not node.name.startswith("_"), "language": "python"})
                bundle["ast_refs"].append({"node_id": f"{sid}#def", "node_type": "FunctionDef", "location": {"path": path, "line": node.lineno, "column": (node.col_offset or 0) + 1, "end_line": node.lineno}, "parent_id": "", "symbol_id": sid, "digest": ""})
            elif isinstance(node, _ast.ClassDef):
                sid = f"{path}:{node.name}"
                defined.setdefault(node.name, sid)
                bundle["symbols"].append({"symbol_id": sid, "kind": "class", "name": node.name, "file": path, "location": {"path": path, "line": node.lineno, "column": (node.col_offset or 0) + 1, "end_line": node.lineno}, "scope": "module", "exported": not node.name.startswith("_"), "language": "python"})
            elif isinstance(node, (_ast.Import, _ast.ImportFrom)):
                bundle.setdefault("_imports", []).append({"path": path, "line": node.lineno, "names": [a.asname or a.name for a in node.names]})
        for node in _ast.walk(tree):
            if isinstance(node, _ast.FunctionDef):
                caller = f"{path}:{node.name}"
                for child in _ast.walk(node):
                    if isinstance(child, _ast.Call) and isinstance(child.func, _ast.Name):
                        bundle.setdefault("_calls", []).append({"caller": caller, "name": child.func.id, "path": path, "line": child.lineno})
        lines = content.splitlines()
        for i, line in enumerate(lines, start=1):
            for framework, pattern in _ROUTE_PATTERNS[:2]:
                match = pattern.search(line)
                if match and path.endswith(".py"):
                    route_path = match.group("path")
                    raw_methods = match.groupdict().get("methods") or match.groupdict().get("method") or "GET"
                    methods = _re.findall(r"[A-Z]+", raw_methods.upper()) or ["GET"]
                    following = lines[i:i + 3] if i < len(lines) else []
                    handler_name = next((_re.search(r"def\s+([A-Za-z_]\w*)", ln) for ln in following if _re.search(r"def\s+([A-Za-z_]\w*)", ln)), None)
                    hid = f"{path}:{handler_name.group(1)}" if handler_name else ""
                    above = [lines[j].strip() for j in range(max(0, i - 4), i - 1) if lines[j].strip().startswith("@") and not pattern.search(lines[j])]
                    between = [ln.strip() for ln in following if ln.strip().startswith("@") and not pattern.search(ln)]
                    decorators = above + between
                    boundary_id = ""
                    for dec in decorators:
                        if _AUTH_HINT.search(dec):
                            boundary_id = f"boundary-{path.replace('/', '-')}-{i}"
                            bundle["boundaries"].append({"boundary_id": boundary_id, "kind": "decorator", "location": {"path": path, "line": i, "column": 1, "end_line": i}, "protects_id": hid, "mechanism": dec[:120], "confidence": "low"})
                            break
                    for method in methods:
                        bundle["endpoints"].append({"endpoint_id": f"{method} {route_path}", "method": method, "path": route_path, "handler_id": hid, "framework": framework, "location": {"path": path, "line": i, "column": 1, "end_line": i}, "auth_boundary_id": boundary_id, "downstream": [], "state_changing": method in _STATE_METHODS})

    # -- javascript/typescript (line patterns, low confidence) -------------

    def _javascript(self, path: str, content: str, bundle: dict[str, Any], defined: dict[str, str]) -> None:
        for i, line in enumerate(content.splitlines(), start=1):
            func = _FUNC_PATTERN.search(line)
            if func:
                name = func.group("name1") or func.group("name2")
                sid = f"{path}:{name}"
                defined.setdefault(name, sid)
                bundle["symbols"].append({"symbol_id": sid, "kind": "function", "name": name, "file": path, "location": {"path": path, "line": i, "column": 1, "end_line": i}, "scope": "module", "exported": "export" in line, "language": detect_language(path)})
            route = _ROUTE_PATTERNS[2][1].search(line)
            if route:
                method = route.group("method").upper()
                route_path = route.group("path")
                bundle["endpoints"].append({"endpoint_id": f"{method} {route_path}", "method": method, "path": route_path, "handler_id": "", "framework": "express", "location": {"path": path, "line": i, "column": 1, "end_line": i}, "auth_boundary_id": "", "downstream": [], "state_changing": method in _STATE_METHODS})

    # -- manifests ----------------------------------------------------------

    def _requirements(self, path: str, content: str, bundle: dict[str, Any]) -> None:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            name = _re.split(r"[=<>!~;\s\[]", line, maxsplit=1)[0].strip()
            version = _re.search(r"([=<>!~]+)\s*([^\s;]+)", line)
            if name:
                bundle["dependency_edges"].append({"importer": path, "package": name, "version": version.group(2) if version else "", "module": name.replace("-", "_"), "reachable": True, "manifest_path": path})

    def _package_json(self, path: str, content: str, bundle: dict[str, Any]) -> None:
        try:
            doc = _json.loads(content)
        except Exception:
            bundle.setdefault("parse_failures", []).append(path)
            return
        deps = {**(doc.get("dependencies", {}) or {}), **(doc.get("devDependencies", {}) or {})}
        for name, version in sorted(deps.items()):
            bundle["dependency_edges"].append({"importer": path, "package": str(name), "version": str(version).lstrip("^~>=< "), "module": str(name), "reachable": True, "manifest_path": path})

    def _cross_file_calls(self, bundle: dict[str, Any], defined: dict[str, str]) -> None:
        for call in bundle.pop("_calls", []):
            target = defined.get(call["name"])
            if target is None:
                continue
            bundle["call_edges"].append({"caller_id": call["caller"], "callee_id": target, "location": {"path": call["path"], "line": call["line"], "column": 1, "end_line": call["line"]}, "confidence": "medium" if target.startswith(call["path"] + ":") else "low", "incomplete": not target.startswith(call["path"] + ":"), "provider": "reference-local"})
        bundle.pop("_imports", None)
