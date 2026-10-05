"""POST-RC-014 — extension layer security invariants.

Four proofs, all behavioral:

* discovery, validation, compatibility, provenance and registration never
  import extension code — hostile modules stay out of ``sys.modules``;
* the single import path is explicit, gated by ``allow_code_load`` and by
  trust, and fails closed on every other route;
* resource reads are package-confined before any I/O;
* the source of the layer itself contains no execution, network, write or
  finding-mutation construct.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from emo_cyber_agent.extensions import (
    ExtensionError,
    ExtensionErrorCode,
    ExtensionLoader,
    ExtensionRegistry,
    ExtensionResource,
    ExtensionResourceKind,
    ExtensionSourceClass,
    load_manifest_file,
    resolve_resource_path,
)

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
SRC = REPO / "src" / "emo_cyber_agent" / "extensions"
FIXTURES = ROOT / "fixtures" / "extensions"
OFFICIAL = FIXTURES / "official"
THIRD = FIXTURES / "third_party"
ADAPTER_DIR = OFFICIAL / "official-verification-adapter"
PACK_ROOT = OFFICIAL / "official-tool-pack"


def resource(path: str, *, resource_id: str = "content") -> ExtensionResource:
    return ExtensionResource(
        resource_id=resource_id, kind=ExtensionResourceKind.TEMPLATE, path=path
    )


# ---------------- no import during the whole read pipeline ----------------

def test_full_ingest_never_imports_extension_code():
    before = set(sys.modules)
    loader = ExtensionLoader(ExtensionRegistry(), allow_code_load=True)
    loader.ingest_directory(OFFICIAL, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)
    loader.ingest_directory(THIRD, source_class=ExtensionSourceClass.THIRD_PARTY)
    assert "hostile_impl" not in sys.modules
    assert "official_adapter_impl" not in sys.modules
    # no module of the layer pulled in external scanner or network stacks
    assert "requests" not in (set(sys.modules) - before)
    assert "subprocess" not in (set(sys.modules) - before)


def test_read_surface_never_imports_extension_code():
    from emo_cyber_agent.extensions import read_extensions

    body = read_extensions(
        "list",
        roots=(
            (ExtensionSourceClass.OFFICIAL_EXTERNAL, OFFICIAL),
            (ExtensionSourceClass.THIRD_PARTY, THIRD),
        ),
    )
    assert body["code_load"] == "disabled"
    assert body["registered"] >= 15
    assert "hostile_impl" not in sys.modules
    assert "official_adapter_impl" not in sys.modules


# ---------------- the single, gated import path ----------------

def test_code_loading_is_off_by_default():
    loader = ExtensionLoader(ExtensionRegistry())
    loader.ingest_directory(OFFICIAL, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)
    with pytest.raises(ExtensionError) as exc:
        loader.load_implementation("official-verification-adapter", "1.0.0")
    assert exc.value.code is ExtensionErrorCode.LOAD_REFUSED
    assert "code loading is disabled" in str(exc.value)


def test_untrusted_content_cannot_be_loaded_even_when_code_loading_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.syspath_prepend(str(THIRD / "conflicting-third-party"))
    loader = ExtensionLoader(ExtensionRegistry(), allow_code_load=True)
    loader.ingest_directory(THIRD, source_class=ExtensionSourceClass.THIRD_PARTY)
    entry = loader.registry.get("conflicting-third-party", "1.0.0")
    assert entry.trust.state.value == "untrusted"
    with pytest.raises(ExtensionError) as exc:
        loader.load_implementation("conflicting-third-party", "1.0.0")
    assert exc.value.code is ExtensionErrorCode.LOAD_REFUSED
    assert "trust does not allow loading" in str(exc.value)
    assert "conflicting_adapter_impl" not in sys.modules


def test_rejected_content_cannot_be_loaded_at_all():
    loader = ExtensionLoader(ExtensionRegistry(), allow_code_load=True)
    loader.ingest_directory(THIRD, source_class=ExtensionSourceClass.THIRD_PARTY)
    with pytest.raises(ExtensionError) as exc:
        loader.load_implementation("malicious-third-party", "1.0.0")
    assert exc.value.code in (ExtensionErrorCode.NOT_FOUND, ExtensionErrorCode.LOAD_REFUSED)
    assert "hostile_impl" not in sys.modules


def test_explicit_trusted_load_imports_exactly_the_declared_target(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.syspath_prepend(str(ADAPTER_DIR))
    loader = ExtensionLoader(ExtensionRegistry(), allow_code_load=True)
    loader.ingest_directory(OFFICIAL, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)
    assert "official_adapter_impl" not in sys.modules
    report = loader.load_implementation("official-verification-adapter", "1.0.0")
    assert report.loaded is True
    assert report.trust_state == "official_trusted"
    assert "official_adapter_impl" in sys.modules
    entry = loader.registry.get("official-verification-adapter", "1.0.0")
    assert entry.lifecycle.value == "loaded"
    assert entry.health.status.value == "healthy"
    # the imported module proves its own side effect was gated, not silent
    import importlib

    loaded_module = importlib.import_module("official_adapter_impl")
    assert loaded_module.IMPORT_SIDE_EFFECTS == ["official_adapter_imported"]
    # isolate: later tests assert discovery imports nothing
    sys.modules.pop("official_adapter_impl", None)


def test_declarative_content_refuses_the_code_path():
    loader = ExtensionLoader(ExtensionRegistry(), allow_code_load=True)
    loader.ingest_directory(OFFICIAL, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)
    with pytest.raises(ExtensionError) as exc:
        loader.load_implementation("official-skill", "1.0.0")
    assert exc.value.code is ExtensionErrorCode.LOAD_REFUSED
    assert "declarative" in str(exc.value)


def test_executable_type_without_an_implementation_is_quarantined_not_imported():
    loader = ExtensionLoader(ExtensionRegistry(), allow_code_load=True)
    loader.ingest_directory(OFFICIAL, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)
    with pytest.raises(ExtensionError) as exc:
        loader.load_implementation("official-tool-pack", "1.0.0")
    assert exc.value.code is ExtensionErrorCode.ENTRYPOINT_INVALID
    entry = loader.registry.get("official-tool-pack", "1.0.0")
    assert entry.lifecycle.value == "quarantined"


def test_import_failure_quarantines_instead_of_retrying():
    loader = ExtensionLoader(ExtensionRegistry(), allow_code_load=True)
    loader.ingest_directory(OFFICIAL, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)

    def _boom(target: str) -> object:
        raise RuntimeError(f"import exploded for {target}")

    with pytest.raises(ExtensionError) as exc:
        loader.load_implementation(
            "official-verification-adapter", "1.0.0", importer=_boom
        )
    assert exc.value.code is ExtensionErrorCode.LOAD_FAILED
    assert "RuntimeError" in str(exc.value)
    entry = loader.registry.get("official-verification-adapter", "1.0.0")
    assert entry.lifecycle.value == "quarantined"
    # a second attempt is refused by lifecycle, not retried
    with pytest.raises(ExtensionError) as retry:
        loader.load_implementation(
            "official-verification-adapter", "1.0.0", importer=_boom
        )
    assert retry.value.code is ExtensionErrorCode.LOAD_REFUSED


# ---------------- package-confined resources ----------------

def test_valid_package_scoped_resource_resolves():
    target = resolve_resource_path(PACK_ROOT, resource("content/pack.yaml"))
    assert target == (PACK_ROOT / "content" / "pack.yaml").resolve()


@pytest.mark.parametrize(
    "path",
    [
        "../official-skill/content/skill.yaml",
        "/etc/passwd",
        "content/../../manifest.extension.yaml",
        "%2e%2e/%2e%2e/etc/passwd",
        "content/pack.yaml\x00.txt",
        "",
    ],
)
def test_hostile_resource_paths_never_become_models(path: str):
    with pytest.raises(ValidationError):
        resource(path)


@pytest.mark.parametrize(
    "path",
    [
        "../official-skill/content/skill.yaml",
        "/etc/passwd",
        "content/../../manifest.extension.yaml",
        "%2e%2e/%2e%2e/etc/passwd",
        "content/pack.yaml\x00.txt",
    ],
)
def test_resource_resolution_refuses_even_a_bypassed_model(path: str):
    bypassed = ExtensionResource.model_construct(
        resource_id="content",
        kind=ExtensionResourceKind.TEMPLATE,
        path=path,
        media_type="",
        digest="",
    )
    with pytest.raises(ExtensionError) as exc:
        resolve_resource_path(PACK_ROOT, bypassed)
    assert exc.value.code is ExtensionErrorCode.RESOURCE_DENIED


def test_missing_resource_is_refused_before_read():
    with pytest.raises(ExtensionError) as exc:
        resolve_resource_path(PACK_ROOT, resource("content/missing.yaml"))
    assert exc.value.code is ExtensionErrorCode.RESOURCE_DENIED


def test_materialization_never_reads_outside_the_package():
    from emo_cyber_agent.extensions import materialize_content

    manifest = load_manifest_file(PACK_ROOT / "manifest.extension.yaml")
    bypassed = ExtensionResource.model_construct(
        resource_id="content",
        kind=ExtensionResourceKind.TEMPLATE,
        path="../../../../../../etc/passwd",
        media_type="",
        digest="",
    )
    hostile = manifest.model_copy(update={"resources": (bypassed,)})
    with pytest.raises(ExtensionError) as exc:
        materialize_content(PACK_ROOT, hostile)
    assert exc.value.code is ExtensionErrorCode.RESOURCE_DENIED


# ---------------- static self-scan of the layer ----------------

def _layer_sources() -> list[Path]:
    return sorted(path for path in SRC.glob("*.py"))


FORBIDDEN_IMPORTS = frozenset(
    {
        "asyncio",
        "cgi",
        "commands",
        "ctypes",
        "ftplib",
        "http",
        "httpx",
        "imaplib",
        "multiprocessing",
        "paramiko",
        "pickle",
        "pip",
        "poplib",
        "pty",
        "requests",
        "shutil",
        "signal",
        "smtplib",
        "socket",
        "smtplib",
        "subprocess",
        "telnetlib",
        "urllib",
        "webbrowser",
        "xmlrpc",
    }
)
FORBIDDEN_CALLS = frozenset({"eval", "exec", "compile", "__import__", "input"})
FORBIDDEN_OS_CALLS = frozenset({"system", "popen", "remove", "removedirs", "rmdir", "rename"})
FORBIDDEN_METHODS = frozenset(
    {"write_text", "write_bytes", "mkdir", "touch", "unlink", "chmod", "mknod"}
)
FORBIDDEN_NAMES = frozenset({"SecurityFinding", "PolicyEngine"})


def _ast_issues(path: Path) -> list[str]:
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    issues: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_IMPORTS:
                    issues.append(f"import:{alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in FORBIDDEN_IMPORTS:
                issues.append(f"from:{node.module}")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id in FORBIDDEN_CALLS:
                    issues.append(f"call:{func.id}")
                if func.id == "open":
                    mode = ""
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                        mode = str(node.args[1].value)
                    for kw in node.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            mode = str(kw.value.value)
                    if any(flag in mode for flag in ("w", "a", "x", "+")):
                        issues.append("write:open")
            elif isinstance(func, ast.Attribute):
                if (
                    isinstance(func.value, ast.Name)
                    and func.value.id == "os"
                    and func.attr in FORBIDDEN_OS_CALLS
                ):
                    issues.append(f"os:{func.attr}")
                if func.attr in FORBIDDEN_METHODS:
                    issues.append(f"method:{func.attr}")
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            issues.append(f"name:{node.id}")
    return issues


def test_layer_contains_fourteen_modules():
    names = sorted(path.name for path in _layer_sources())
    assert len(names) == 14, names
    assert names == [
        "__init__.py",
        "catalog.py",
        "compatibility.py",
        "conflicts.py",
        "discovery.py",
        "errors.py",
        "loader.py",
        "manifest.py",
        "provenance.py",
        "registry.py",
        "resolver.py",
        "spec.py",
        "trust.py",
        "validator.py",
    ]


def test_layer_source_has_no_execution_network_or_write_construct():
    offenders: list[str] = []
    for path in _layer_sources():
        for issue in _ast_issues(path):
            offenders.append(f"{path.name}:{issue}")
    assert offenders == []


def test_only_the_loader_may_reach_importlib_import():
    hits = [
        path.name
        for path in _layer_sources()
        if "import_module" in path.read_text(encoding="utf-8")
    ]
    assert hits == ["loader.py"]


def test_layer_imports_are_limited_to_documented_bridges():
    import ast

    allowed_modules = {
        "__future__",
        "collections",
        "emo_cyber_agent",
        "enum",
        "hashlib",
        "importlib",
        "json",
        "jsonschema",
        "os",
        "pathlib",
        "platform",
        "pydantic",
        "re",
        "sys",
        "typing",
        "yaml",
    }
    offending: list[str] = []
    for path in _layer_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] not in allowed_modules:
                        offending.append(f"{path.name}:{alias.name}")
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root not in allowed_modules:
                    offending.append(f"{path.name}:{node.module}")
    assert offending == []
