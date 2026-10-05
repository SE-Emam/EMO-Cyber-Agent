"""In-memory RepositoryPort for offline unit/contract/security tests.

No network, no credentials, no global mutable state shared across audits.
Each instance is independent; callers pass their own AuditRepositoryScope
through RepositoryService (Core), never through this adapter.
"""

from __future__ import annotations

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
    validate_ref,
)


class InMemoryRepositoryProvider(RepositoryPort):
    """Test double. Fetch → map → return. No security decisions."""

    def __init__(
        self,
        identity: RepositoryIdentity,
        files: dict[str, str],
        commits: dict[str, dict[str, str]] | None = None,
    ):
        self._identity = identity
        # normalize keys at construction; reject traversal early
        self._files: dict[str, str] = {normalize_path(k): v for k, v in files.items()}
        self._commits = commits or {
            identity.ref: {"sha": "abc123def456abc123def456abc123def456abcd", "author": "test", "at": "2026-01-01T00:00:00+00:00", "message": "init"},
        }

    def _check(self, identity: RepositoryIdentity) -> None:
        if (
            identity.provider != self._identity.provider
            or identity.owner != self._identity.owner
            or identity.repo != self._identity.repo
        ):
            raise RepositoryError(RepositoryErrorCode.REPOSITORY_NOT_FOUND, "unknown repository")

    def resolve_repository(self, identity: RepositoryIdentity) -> Repository:
        self._check(identity)
        return Repository(identity=identity, name=identity.repo, description="mock repo", default_branch=identity.ref, private=False, provider=identity.provider)

    def get_metadata(self, identity: RepositoryIdentity) -> Repository:
        return self.resolve_repository(identity)

    def list_tree(self, identity: RepositoryIdentity, path: str = "") -> RepositoryTree:
        self._check(identity)
        clean = normalize_path(path) if path else ""
        prefix = f"{clean}/" if clean else ""
        entries: list[RepositoryTreeEntry] = []
        seen_dirs: set[str] = set()
        for fp, content in self._files.items():
            if not fp.startswith(prefix):
                continue
            rest = fp[len(prefix):]
            if "/" in rest:
                d = rest.split("/", 1)[0]
                if d not in seen_dirs:
                    seen_dirs.add(d)
                    entries.append(RepositoryTreeEntry(path=f"{prefix}{d}", kind="dir"))
            else:
                entries.append(RepositoryTreeEntry(path=fp, kind="file", sha=content_digest(content)[:12], size=len(content)))
        return RepositoryTree(identity=identity, path=clean, entries=tuple(sorted(entries, key=lambda e: e.path)))

    def get_file(self, identity: RepositoryIdentity, path: str) -> RepositoryFile:
        self._check(identity)
        clean = normalize_path(path)
        if clean not in self._files:
            raise RepositoryError(RepositoryErrorCode.FILE_NOT_FOUND, f"not found: {clean}")
        content = self._files[clean]
        return RepositoryFile(
            identity=identity,
            path=clean,
            ref=identity.ref,
            sha=content_digest(content)[:12],
            content_digest=content_digest(content),
            untrusted=mark_untrusted(content),
            content=content,
        )

    def search_code(self, identity: RepositoryIdentity, query: str) -> list[CodeSearchResult]:
        self._check(identity)
        if not query.strip():
            raise RepositoryError(RepositoryErrorCode.SEARCH_FAILED, "empty query")
        out: list[CodeSearchResult] = []
        for fp, content in self._files.items():
            for i, line in enumerate(content.splitlines(), start=1):
                if query.lower() in line.lower():
                    out.append(
                        CodeSearchResult(
                            identity=identity,
                            path=fp,
                            line=i,
                            snippet_digest=content_digest(line),
                            untrusted_snippet=mark_untrusted(line),
                        )
                    )
        return out

    def get_commit(self, identity: RepositoryIdentity, ref: str) -> CommitInfo:
        self._check(identity)
        clean = validate_ref(ref)
        c = self._commits.get(clean) or self._commits.get(identity.ref)
        if not c:
            raise RepositoryError(RepositoryErrorCode.INVALID_REF, f"unknown ref: {clean}")
        return CommitInfo(
            identity=identity,
            sha=c["sha"],
            message_digest=content_digest(c.get("message", "")),
            author=c.get("author", ""),
            committed_at=c.get("at", ""),
        )
