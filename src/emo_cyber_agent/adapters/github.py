"""GitHub read-only adapter behind RepositoryPort — ECA-T005.

Fetch → map → return. No severity, no classification, no permission logic.
No write operations exist in this module by design (no PR/push/merge/issue).

Credential boundary:
- The adapter accepts a `token_ref` (reference name, e.g. env var name),
  NEVER a raw token value, and never persists credential material.
- `redact_credentials` is applied to every error, summary, and mapped field.
- Transport is injectable (`transport` callable) so unit tests run offline.
  Real network use requires explicit opt-in integration tests with secrets.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any, Callable

from emo_cyber_agent.core.repository import (
    CodeSearchResult,
    CommitInfo,
    Repository,
    RepositoryError,
    RepositoryErrorCode,
    RepositoryFile,
    RepositoryIdentity,
    RepositoryPort,
    RepositoryTree,
    RepositoryTreeEntry,
    content_digest,
    mark_untrusted,
    normalize_path,
    redact_credentials,
    validate_ref,
)

Transport = Callable[[str, dict[str, str]], tuple[int, Any]]


def _default_transport(url: str, headers: dict[str, str]) -> tuple[int, Any]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 (explicit read-only GET)
            return resp.status, json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:  # normalize at boundary; never leak provider internals
        raise RepositoryError(RepositoryErrorCode.PROVIDER_ERROR, redact_credentials(str(e))) from e


def _status_to_error(status: int, body: Any, *, what: str) -> RepositoryError:
    text = redact_credentials(json.dumps(body)[:300] if not isinstance(body, str) else body[:300])
    if status == 404:
        code = RepositoryErrorCode.REPOSITORY_NOT_FOUND if what == "repo" else RepositoryErrorCode.FILE_NOT_FOUND
        return RepositoryError(code, f"{what} not found")
    if status in (401, 403):
        msg = str(body)[:200] if isinstance(body, str) else json.dumps(body)[:200]
        if "rate limit" in redact_credentials(msg).lower():
            return RepositoryError(RepositoryErrorCode.RATE_LIMITED, "provider rate limited")
        return RepositoryError(RepositoryErrorCode.AUTHENTICATION_FAILED, "authentication failed")
    if status == 422:
        return RepositoryError(RepositoryErrorCode.SEARCH_FAILED, f"search failed: {text[:120]}")
    return RepositoryError(RepositoryErrorCode.PROVIDER_ERROR, f"provider error ({status}): {text[:120]}")


class GitHubRepositoryAdapter(RepositoryPort):
    """Read-only GitHub adapter. `token_ref` is a reference, not a secret."""

    API = "https://api.github.com"

    def __init__(self, *, token_ref: str | None = None, transport: Transport | None = None):
        if token_ref and len(token_ref) > 128:
            raise ValueError("token_ref must be a reference name, not a secret value")
        # Refuse values that look like raw secrets.
        if token_ref and any(s in token_ref for s in ("ghp_", "github_pat_", "gho_")):
            raise ValueError("token_ref must be a reference name, never a raw token")
        self._token_ref = token_ref
        self._transport: Transport = transport or _default_transport

    def _headers(self) -> dict[str, str]:
        # NOTE: real token resolution happens in deployment, never logged.
        # The reference name itself carries no secret material.
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "emo-cyber-agent/0.1.0"}
        return headers

    def _get(self, path: str, *, what: str) -> Any:
        url = f"{self.API}{path}"
        status, body = self._transport(url, self._headers())
        if status != 200:
            raise _status_to_error(status, body, what=what)
        return body

    def resolve_repository(self, identity: RepositoryIdentity) -> Repository:
        if identity.provider != "github":
            raise RepositoryError(RepositoryErrorCode.REPOSITORY_NOT_FOUND, "not a github identity")
        body = self._get(f"/repos/{identity.owner}/{identity.repo}", what="repo")
        return Repository(
            identity=identity,
            name=redact_credentials(str(body.get("name", identity.repo))),
            description=redact_credentials(str(body.get("description") or ""))[:500],
            default_branch=str(body.get("default_branch") or identity.ref),
            private=bool(body.get("private", False)),
            provider="github",
        )

    def get_metadata(self, identity: RepositoryIdentity) -> Repository:
        return self.resolve_repository(identity)

    def list_tree(self, identity: RepositoryIdentity, path: str = "") -> RepositoryTree:
        clean = normalize_path(path) if path else ""
        ref = validate_ref(identity.ref)
        query = "?recursive=1" if not clean else ""
        body = self._get(f"/repos/{identity.owner}/{identity.repo}/git/trees/{urllib.parse.quote(ref)}{query}", what="repo")
        tree = body.get("tree", []) if isinstance(body, dict) else []
        entries: list[RepositoryTreeEntry] = []
        prefix = f"{clean}/" if clean else ""
        for node in tree:
            p = str(node.get("path", ""))
            if clean and not (p == clean or p.startswith(prefix)):
                continue
            kind = "dir" if node.get("type") == "tree" else "file"
            entries.append(RepositoryTreeEntry(path=p, kind=kind, sha=str(node.get("sha", ""))[:12] or None))
        truncated = bool(isinstance(body, dict) and body.get("truncated", False))
        return RepositoryTree(identity=identity, path=clean, entries=tuple(entries[:500]), truncated=truncated)

    def get_file(self, identity: RepositoryIdentity, path: str) -> RepositoryFile:
        clean = normalize_path(path)
        ref = validate_ref(identity.ref)
        import base64

        body = self._get(
            f"/repos/{identity.owner}/{identity.repo}/contents/{urllib.parse.quote(clean)}?ref={urllib.parse.quote(ref)}",
            what="file",
        )
        if not isinstance(body, dict) or body.get("type") not in (None, "file") or "content" not in body:
            raise RepositoryError(RepositoryErrorCode.FILE_NOT_FOUND, f"not found: {clean}")
        try:
            raw = base64.b64decode(body["content"]).decode("utf-8", errors="replace")
        except Exception as e:
            raise RepositoryError(RepositoryErrorCode.CONTENT_UNAVAILABLE, "undecodable content") from e
        sha = redact_credentials(str(body.get("sha", "")))[:40]
        return RepositoryFile(
            identity=identity,
            path=clean,
            ref=ref,
            sha=sha or None,
            content_digest=content_digest(raw),
            untrusted=mark_untrusted(raw),
            content=raw,
        )

    def search_code(self, identity: RepositoryIdentity, query: str) -> list[CodeSearchResult]:
        if not query.strip():
            raise RepositoryError(RepositoryErrorCode.SEARCH_FAILED, "empty query")
        q = urllib.parse.quote(f"{query.strip()} repo:{identity.owner}/{identity.repo}")
        body = self._get(f"/search/code?q={q}&per_page=20", what="search")
        items = body.get("items", []) if isinstance(body, dict) else []
        out: list[CodeSearchResult] = []
        for item in items:
            p = redact_credentials(str(item.get("path", "")))[:512]
            if not p:
                continue
            try:
                p = normalize_path(p)
            except RepositoryError:
                continue
            out.append(CodeSearchResult(identity=identity, path=p, line=None, snippet_digest=content_digest(p), untrusted_snippet=mark_untrusted(p)))
        return out

    def get_commit(self, identity: RepositoryIdentity, ref: str) -> CommitInfo:
        clean = validate_ref(ref)
        body = self._get(f"/repos/{identity.owner}/{identity.repo}/commits/{urllib.parse.quote(clean)}", what="repo")
        if not isinstance(body, dict):
            raise RepositoryError(RepositoryErrorCode.INVALID_REF, f"unknown ref: {clean}")
        sha = redact_credentials(str(body.get("sha", "")))[:40]
        commit = body.get("commit", {}) if isinstance(body.get("commit"), dict) else {}
        author = redact_credentials(str((commit.get("author") or {}).get("name", "")))[:120]
        when = str((commit.get("author") or {}).get("date", ""))
        msg = str(commit.get("message", ""))
        return CommitInfo(identity=identity, sha=sha, message_digest=content_digest(msg), author=author, committed_at=when)
