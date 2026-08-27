#!/usr/bin/env python3
"""Enforce ADR 0005 C1's narrow provider-serialization boundary.

This checker resolves Cargo dependency declarations structurally, including
target/dev/build tables, workspace inheritance, aliases, and feature
forwarding. Rust sources are scanned by a lexical scanner so comments and
string literals cannot create or hide policy matches; literal include! targets
are recursively scanned while dynamic include! paths fail closed. The
locked-graph mode uses cargo metadata --locked as the authoritative feature
evidence.
"""

from __future__ import annotations

import argparse
import ast
import copy
import json
import pathlib
import re
import subprocess
import tempfile
import textwrap
import tomllib
from dataclasses import dataclass, field


EXPECTED = {"protocol", "crypto", "store", "relay", "client", "cli"}
CBOR_PACKAGE = "cbor4ii"
CRYPTO_PACKAGE = "telegraph-crypto"
PROTOCOL_PACKAGE = "telegraph-protocol"
BOUNDARY_PATHS = {
    CRYPTO_PACKAGE: pathlib.PurePosixPath("crates/crypto"),
    PROTOCOL_PACKAGE: pathlib.PurePosixPath("crates/protocol"),
}
FORBIDDEN_PROVIDER_PACKAGES = {"vodozemac", "matrix-pickle", "serde", "serde_derive", "serde_json"}
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
EXPECTED_CBOR_PACKAGE_ID = f"{CRATES_IO_SOURCE}#cbor4ii@1.2.2"
DEPENDENCY_SECTIONS = {"dependencies", "dev-dependencies", "build-dependencies"}
FEATURE_FORWARDING = re.compile(r"^(?P<alias>[A-Za-z0-9_-]+)\??/(?P<feature>[A-Za-z0-9_-]+)$")
IDENTIFIER_START = re.compile(r"[A-Za-z_]")
IDENTIFIER_CONTINUE = re.compile(r"[A-Za-z0-9_]")


class CheckFailure(RuntimeError):
    pass


@dataclass
class Crate:
    path: pathlib.Path
    name: str
    manifest: dict


@dataclass
class DependencyEdge:
    crate: Crate
    alias: str
    package: str
    features: set[str]
    context: str
    spec: dict | str | bool
    inherited: bool = False
    declared_features: set[str] = field(default_factory=set)


@dataclass
class PolicyReport:
    crates: list[Crate]
    edges: list[DependencyEdge]
    crypto_serde_edges: list[DependencyEdge] = field(default_factory=list)


@dataclass(frozen=True)
class Token:
    value: str
    line: int
    kind: str = "token"
    literal: str | None = None


def normalise(value: str) -> str:
    return value.replace("\\", "/").rstrip("/")


def read_toml(path: pathlib.Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CheckFailure(f"{path}: cannot parse manifest: {exc}") from exc


def crates(root: pathlib.Path) -> list[Crate]:
    crates_root = root / "crates"
    result: list[Crate] = []
    if not crates_root.is_dir():
        return result
    for manifest_path in sorted(crates_root.rglob("Cargo.toml")):
        if "target" in manifest_path.parts:
            continue
        manifest = read_toml(manifest_path)
        package = manifest.get("package", {})
        name = package.get("name")
        if not isinstance(name, str) or not name:
            raise CheckFailure(f"{manifest_path}: missing package.name")
        result.append(Crate(manifest_path.parent.resolve(), name, manifest))
    return result


def dependency_tables(value: dict, prefix: tuple[str, ...] = ()):
    """Yield normal and target-specific dependency tables recursively."""

    for key in DEPENDENCY_SECTIONS:
        table = value.get(key)
        if isinstance(table, dict):
            yield ".".join(prefix + (key,)), table
    for key, child in value.items():
        if key in DEPENDENCY_SECTIONS or not isinstance(child, dict):
            continue
        yield from dependency_tables(child, prefix + (str(key),))


def workspace_dependency_table(root_manifest: dict) -> dict:
    dependencies = root_manifest.get("workspace", {}).get("dependencies", {})
    if not isinstance(dependencies, dict):
        raise CheckFailure("root workspace.dependencies must be a TOML table")
    return dependencies


def dependency_spec(
    alias: str,
    spec: dict | str | bool,
    workspace_dependencies: dict,
) -> tuple[str, set[str], dict | str | bool, bool]:
    """Resolve actual package identity and features, including workspace=true."""

    inherited = spec is True or (isinstance(spec, dict) and spec.get("workspace") is True)
    effective: dict | str | bool = spec
    if inherited:
        if alias not in workspace_dependencies:
            raise CheckFailure(
                f"dependency {alias!r} uses workspace=true but is absent from root workspace.dependencies"
            )
        parent = workspace_dependencies[alias]
        if parent is True:
            raise CheckFailure(f"root workspace dependency {alias!r} cannot itself be workspace=true")
        parent_spec = dict(parent) if isinstance(parent, dict) else {"version": parent}
        local = spec if isinstance(spec, dict) else {}
        if "package" in local and local["package"] != parent_spec.get("package", alias):
            raise CheckFailure(
                f"dependency {alias!r}: workspace=true package conflicts with root workspace dependency"
            )
        if "features" in local and not isinstance(local["features"], list):
            raise CheckFailure(f"dependency {alias!r}: workspace=true features must be an array of strings")
        parent_features = parent_spec.get("features", [])
        if not isinstance(parent_features, list) or not all(isinstance(item, str) for item in parent_features):
            raise CheckFailure(f"root workspace dependency {alias!r}: features must be an array of strings")
        merged = dict(parent_spec)
        merged["features"] = list(parent_features) + list(local.get("features", []))
        for key in ("default-features", "optional"):
            if key in local:
                merged[key] = local[key]
        effective = merged

    if isinstance(effective, dict):
        package = effective.get("package", alias)
        if not isinstance(package, str) or not package:
            raise CheckFailure(f"dependency {alias!r}: package must be a non-empty string")
        raw_features = effective.get("features", [])
        if not isinstance(raw_features, list) or not all(isinstance(item, str) for item in raw_features):
            raise CheckFailure(f"dependency {alias!r}: features must be an array of strings")
        return package, set(raw_features), effective, inherited
    return alias, set(), effective, inherited


def dependency_version(spec: dict | str | bool) -> str | None:
    if isinstance(spec, dict):
        value = spec.get("version")
    elif isinstance(spec, str):
        value = spec
    else:
        value = None
    return value if isinstance(value, str) else None


def dependency_edges(crate: Crate, root_manifest: dict) -> list[DependencyEdge]:
    workspace_dependencies = workspace_dependency_table(root_manifest)
    edges: list[DependencyEdge] = []
    for context, table in dependency_tables(crate.manifest):
        for alias, spec in table.items():
            if not isinstance(alias, str):
                raise CheckFailure(f"{crate.path / 'Cargo.toml'}: dependency alias is not a string")
            if not isinstance(spec, (dict, str, bool)):
                raise CheckFailure(f"{crate.path / 'Cargo.toml'}: dependency {alias!r} has unsupported TOML shape")
            package, features, effective, inherited = dependency_spec(alias, spec, workspace_dependencies)
            declared_features = set(features)
            edges.append(
                DependencyEdge(
                    crate=crate,
                    alias=alias,
                    package=package,
                    features=features,
                    context=context,
                    spec=effective,
                    inherited=inherited,
                    declared_features=declared_features,
                )
            )

    # Cargo feature forwarding can request a dependency feature without
    # spelling it in the dependency table: alias?/serde1 and alias/serde1.
    aliases: dict[str, list[DependencyEdge]] = {}
    for edge in edges:
        aliases.setdefault(edge.alias, []).append(edge)
    features = crate.manifest.get("features", {})
    if isinstance(features, dict):
        for values in features.values():
            if not isinstance(values, list):
                continue
            for value in values:
                if not isinstance(value, str):
                    continue
                match = FEATURE_FORWARDING.fullmatch(value)
                if match is None:
                    continue
                matching_edges = aliases.get(match.group("alias"), [])
                if not matching_edges:
                    raise CheckFailure(
                        f"{crate.path / 'Cargo.toml'}: feature forwarding {value!r} has no dependency alias"
                    )
                for edge in matching_edges:
                    edge.features.add(match.group("feature"))
    return edges


def source_files(crate: Crate) -> list[pathlib.Path]:
    return sorted(
        path
        for path in crate.path.rglob("*.rs")
        if path.relative_to(crate.path).parts[:1] not in (("target",), (".git",))
    )


def _consume_line_comment(source: str, index: int) -> int:
    end = source.find("\n", index)
    return len(source) if end < 0 else end


def _consume_block_comment(source: str, index: int) -> int:
    depth = 1
    cursor = index + 2
    while cursor < len(source) and depth:
        if source.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif source.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor


def _consume_quoted(source: str, index: int, quote: str) -> int:
    cursor = index + 1
    while cursor < len(source):
        if source[cursor] == "\\":
            cursor += 2
        elif source[cursor] == quote:
            return cursor + 1
        else:
            cursor += 1
    return cursor


def _char_literal_end(source: str, index: int) -> int | None:
    cursor = index + 1
    if cursor >= len(source) or source[cursor] in "\r\n":
        return None
    if source[cursor] == "\\":
        cursor += 2
    else:
        cursor += 1
    if cursor < len(source) and source[cursor] == "'":
        return cursor + 1
    return None


def _raw_string_start(source: str, index: int) -> tuple[int, int] | None:
    match = re.match(r'(?:br|r)(?P<hashes>#*)"', source[index:])
    if match is None:
        return None
    quote = index + match.end() - 1
    return quote, len(match.group("hashes"))


def _consume_raw_string(source: str, quote: int, hashes: int) -> int:
    terminator = '"' + ("#" * hashes)
    end = source.find(terminator, quote + 1)
    return len(source) if end < 0 else end + len(terminator)


def rust_tokens(source: str, *, retain_literals: bool = False) -> list[Token]:
    """Tokenize policy-relevant identifiers while skipping lexical trivia.

    The normal policy scan discards literals.  The include! policy asks for a
    second, still lexical, pass that retains only string/byte-string literals
    so a path can be resolved without treating comments or string contents as
    Rust code.
    """

    tokens: list[Token] = []
    index = 0
    line = 1
    length = len(source)

    def consume(end: int) -> None:
        nonlocal index, line
        line += source[index:end].count("\n")
        index = end

    while index < length:
        current = source[index]
        if current.isspace():
            consume(index + 1)
            continue
        if source.startswith("//", index):
            consume(_consume_line_comment(source, index))
            continue
        if source.startswith("/*", index):
            consume(_consume_block_comment(source, index))
            continue

        raw = _raw_string_start(source, index)
        if raw is not None:
            quote, hashes = raw
            end = _consume_raw_string(source, quote, hashes)
            if retain_literals:
                terminator = '"' + ("#" * hashes)
                content_end = end - len(terminator)
                tokens.append(Token("<literal>", line, "literal", source[quote + 1 : content_end]))
            consume(end)
            continue
        if current == "b" and index + 1 < length and source[index + 1] == '"':
            end = _consume_quoted(source, index + 1, '"')
            if retain_literals:
                tokens.append(Token("<byte-literal>", line, "byte-literal", source[index + 2 : end - 1]))
            consume(end)
            continue
        if current == '"':
            end = _consume_quoted(source, index, '"')
            if retain_literals:
                tokens.append(Token("<literal>", line, "literal", source[index + 1 : end - 1]))
            consume(end)
            continue
        if current == "'":
            # A lifetime such as 'static has no closing quote and remains
            # tokenized. A character literal is skipped as one unit.
            end = _char_literal_end(source, index)
            if end is not None:
                consume(end)
                continue

        if IDENTIFIER_START.fullmatch(current):
            end = index + 1
            while end < length and IDENTIFIER_CONTINUE.fullmatch(source[end]):
                end += 1
            tokens.append(Token(source[index:end], line))
            consume(end)
            continue
        if source.startswith("::", index):
            tokens.append(Token("::", line))
            consume(index + 2)
            continue
        tokens.append(Token(current, line))
        consume(index + 1)
    return tokens


def _pathlike(tokens: list[Token], index: int) -> bool:
    previous = tokens[index - 1].value if index else None
    following = tokens[index + 1].value if index + 1 < len(tokens) else None
    return previous in {"::", "use", "crate", "extern"} or following == "::"


def _decode_include_literal(token: Token) -> str | None:
    """Decode an include! string token, failing closed for Rust-only escapes."""

    if token.kind != "literal" or token.literal is None:
        return None
    try:
        value = ast.literal_eval('"' + token.literal + '"')
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _include_target(
    path: pathlib.Path,
    tokens: list[Token],
    index: int,
    crate_root: pathlib.Path,
    violations: list[str],
) -> pathlib.Path | None:
    """Validate an include! invocation and return its bounded literal target."""

    if index + 2 >= len(tokens) or tokens[index + 1].value != "!":
        return None
    if tokens[index + 2].value != "(":
        violations.append(f"{path}:{tokens[index].line}: include! must have a parenthesized argument")
        return None
    depth = 0
    close = None
    for cursor in range(index + 2, len(tokens)):
        value = tokens[cursor].value
        if value == "(":
            depth += 1
        elif value == ")":
            depth -= 1
            if depth == 0:
                close = cursor
                break
    if close is None:
        violations.append(f"{path}:{tokens[index].line}: include! has an unterminated argument")
        return None
    arguments = tokens[index + 3 : close]
    if len(arguments) != 1 or arguments[0].kind != "literal":
        violations.append(
            f"{path}:{tokens[index].line}: include! requires one literal path; dynamic concat!/env!/OUT_DIR paths are forbidden"
        )
        return None
    relative = _decode_include_literal(arguments[0])
    if relative is None or not relative:
        violations.append(f"{path}:{tokens[index].line}: include! literal path is invalid")
        return None
    target = (path.parent / pathlib.Path(relative)).resolve()
    try:
        target.relative_to(crate_root)
    except ValueError:
        violations.append(f"{path}:{tokens[index].line}: include! target escapes the crate boundary")
        return None
    if not target.is_file():
        violations.append(f"{path}:{tokens[index].line}: include! target does not exist: {relative!r}")
        return None
    return target


def boundary_role(root: pathlib.Path, crate: Crate) -> str | None:
    for package, relative in BOUNDARY_PATHS.items():
        if crate.name == package and crate.path == (root / pathlib.Path(relative)).resolve():
            return package
    return None


def boundary_identity_violations(root: pathlib.Path, found: list[Crate]) -> list[str]:
    violations: list[str] = []
    canonical = {
        package: (root / pathlib.Path(relative)).resolve()
        for package, relative in BOUNDARY_PATHS.items()
    }
    for crate in found:
        for package, expected_path in canonical.items():
            if crate.name == package and crate.path != expected_path:
                violations.append(
                    f"{crate.path / 'Cargo.toml'}: package {package!r} is privileged only at {expected_path}"
                )
            if crate.path == expected_path and crate.name != package:
                violations.append(
                    f"{crate.path / 'Cargo.toml'}: canonical {expected_path} must declare package {package!r}"
                )
    return violations


def source_violations(root: pathlib.Path, crate: Crate) -> list[str]:
    violations: list[str] = []
    role = boundary_role(root, crate)
    pending = list(source_files(crate))
    seen: set[pathlib.Path] = set()
    while pending:
        path = pending.pop()
        path = path.resolve()
        if path in seen:
            continue
        seen.add(path)
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CheckFailure(f"{path}: cannot read source: {exc}") from exc
        tokens = rust_tokens(source, retain_literals=True)
        for index, token in enumerate(tokens):
            if role != CRYPTO_PACKAGE and token.value == "include":
                target = _include_target(path, tokens, index, crate.path.resolve(), violations)
                if target is not None:
                    pending.append(target)
            if token.value == "cbor4ii":
                if not _pathlike(tokens, index):
                    continue
                is_core_path = (
                    index + 2 < len(tokens)
                    and tokens[index + 1].value == "::"
                    and tokens[index + 2].value == "core"
                )
                if role == PROTOCOL_PACKAGE:
                    if not is_core_path:
                        violations.append(
                            f"{path}:{token.line}: protocol cbor4ii path must be the exact cbor4ii::core path"
                        )
                elif role != CRYPTO_PACKAGE:
                    violations.append(f"{path}:{token.line}: non-crypto cbor4ii source use")
            if role != CRYPTO_PACKAGE and token.value in {
                "AccountPickle",
                "SessionPickle",
            }:
                violations.append(f"{path}:{token.line}: direct provider pickle/Serde model use")
            if role != CRYPTO_PACKAGE and token.value in {
                "vodozemac",
                "matrix_pickle",
                "serde_json",
                "serde",
            } and _pathlike(tokens, index):
                violations.append(f"{path}:{token.line}: direct provider pickle/Serde path use")
            if role == PROTOCOL_PACKAGE and token.value == "serde" and _pathlike(tokens, index):
                violations.append(f"{path}:{token.line}: protocol source contains Serde")
    return violations


def check_repository(root: pathlib.Path) -> PolicyReport:
    root_manifest = read_toml(root / "Cargo.toml")
    found = crates(root)
    if not found:
        raise CheckFailure("no crates/**/Cargo.toml manifests found")
    all_edges: list[DependencyEdge] = []
    crypto_serde_edges: list[DependencyEdge] = []
    violations: list[str] = boundary_identity_violations(root, found)

    for crate in found:
        role = boundary_role(root, crate)
        edges = dependency_edges(crate, root_manifest)
        all_edges.extend(edges)
        for edge in edges:
            if edge.package in FORBIDDEN_PROVIDER_PACKAGES and role != CRYPTO_PACKAGE:
                violations.append(
                    f"{crate.path / 'Cargo.toml'}: {edge.context} edge {edge.alias!r} resolves to forbidden "
                    f"provider package {edge.package!r} outside telegraph-crypto"
                )
            if edge.package != CBOR_PACKAGE:
                continue
            if dependency_version(edge.spec) != "=1.2.2":
                violations.append(
                    f"{crate.path / 'Cargo.toml'}: {edge.context} cbor4ii edge must exact-pin version =1.2.2"
                )
            if role == PROTOCOL_PACKAGE:
                if edge.alias != CBOR_PACKAGE:
                    violations.append(
                        f"{crate.path / 'Cargo.toml'}: protocol cbor4ii dependency must use the exact alias cbor4ii"
                    )
                if edge.features:
                    violations.append(
                        f"{crate.path / 'Cargo.toml'}: protocol cbor4ii edge requests optional features "
                        f"{sorted(edge.features)}; only the core no-feature edge is allowed"
                    )
                if isinstance(edge.spec, dict) and edge.spec.get("default-features", True) is not False:
                    violations.append(
                        f"{crate.path / 'Cargo.toml'}: protocol cbor4ii edge must disable default features"
                    )
            elif role != CRYPTO_PACKAGE:
                violations.append(
                    f"{crate.path / 'Cargo.toml'}: {edge.context} direct cbor4ii edge is allowed only for "
                    "telegraph-protocol core or telegraph-crypto provider state"
                )
            if role == CRYPTO_PACKAGE:
                if edge.alias != CBOR_PACKAGE:
                    violations.append(
                        f"{crate.path / 'Cargo.toml'}: crypto cbor4ii dependency must use the exact alias cbor4ii"
                    )
                if not isinstance(edge.spec, dict) or edge.spec.get("default-features", True) is not False:
                    violations.append(
                        f"{crate.path / 'Cargo.toml'}: crypto cbor4ii edge must disable default features"
                    )
                if edge.declared_features != {"serde1"}:
                    violations.append(
                        f"{crate.path / 'Cargo.toml'}: crypto cbor4ii manifest edge must directly request exactly ['serde1']; "
                        f"observed {sorted(edge.declared_features)}"
                    )
                if edge.features != {"serde1"}:
                    violations.append(
                        f"{crate.path / 'Cargo.toml'}: crypto cbor4ii edge including feature forwarding must request exactly ['serde1']; "
                        f"observed {sorted(edge.features)}"
                    )
                crypto_serde_edges.append(edge)
        violations.extend(source_violations(root, crate))

    workspace_dependencies = workspace_dependency_table(root_manifest)
    for alias, spec in workspace_dependencies.items():
        if not isinstance(spec, (dict, str, bool)):
            raise CheckFailure(f"root workspace dependency {alias!r} has unsupported TOML shape")
        package, features, _, _ = dependency_spec(alias, spec, {})
        if package == CBOR_PACKAGE:
            effective_spec = dependency_spec(alias, spec, {})[2]
            if dependency_version(effective_spec) != "=1.2.2":
                violations.append(
                    f"root workspace.dependencies edge {alias!r} must exact-pin cbor4ii version =1.2.2"
                )
            if "serde1" in features and not any(
                edge.package == CBOR_PACKAGE and edge.alias == alias and "serde1" in edge.features
                for edge in all_edges
            ):
                violations.append(
                    f"root workspace.dependencies edge {alias!r} requests cbor4ii serde1 without a concrete crate edge"
                )

    crypto_manifest_present = any(boundary_role(root, crate) == CRYPTO_PACKAGE for crate in found)
    if crypto_manifest_present and len(crypto_serde_edges) != 1:
        violations.append(
            "exactly one telegraph-crypto dependency edge must request cbor4ii serde1 "
            f"(observed {len(crypto_serde_edges)})"
        )
    if violations:
        raise CheckFailure("\n".join(f"FAIL: {item}" for item in violations))
    return PolicyReport(found, all_edges, crypto_serde_edges)


def workspace_sets(root: pathlib.Path) -> tuple[set[str], set[str], set[str], set[str]]:
    manifest = read_toml(root / "Cargo.toml")
    workspace = manifest.get("workspace", {})
    metadata = workspace.get("metadata", {}).get("telegraph", {})
    expected_names = metadata.get("expected_crates", [])
    delivered_names = metadata.get("delivered_crates", [])
    if set(expected_names) != EXPECTED or len(expected_names) != len(EXPECTED):
        raise CheckFailure("expected_crates metadata must contain exactly the six boundary crates")
    if len(delivered_names) != len(set(delivered_names)):
        raise CheckFailure("delivered_crates metadata is duplicated")
    if not set(delivered_names).issubset(EXPECTED):
        raise CheckFailure("delivered_crates must be a subset of expected_crates")
    expected = {f"crates/{name}" for name in expected_names}
    delivered = {f"crates/{name}" for name in delivered_names}
    members = {normalise(str(item)) for item in workspace.get("members", [])}
    excluded = {normalise(str(item)) for item in workspace.get("exclude", [])}
    return expected, delivered, members, excluded


def _metadata_graph(root: pathlib.Path) -> dict:
    try:
        result = subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout).strip()
        raise CheckFailure(f"cargo metadata --locked failed: {detail}") from exc
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CheckFailure(f"cargo metadata returned invalid JSON: {exc}") from exc


def validate_locked_metadata(graph: dict, report: PolicyReport) -> tuple[str, str, str, set[str]]:
    packages = [package for package in graph.get("packages", []) if package.get("name") == CBOR_PACKAGE]
    if len(packages) != 1:
        raise CheckFailure(f"locked metadata must contain exactly one cbor4ii package ID (found {len(packages)})")
    package = packages[0]
    package_id = package.get("id")
    source = package.get("source")
    version = package.get("version")
    if not isinstance(package_id, str) or not package_id:
        raise CheckFailure("locked cbor4ii package is missing an exact package ID")
    if package_id != EXPECTED_CBOR_PACKAGE_ID:
        raise CheckFailure(
            f"locked cbor4ii package ID must be {EXPECTED_CBOR_PACKAGE_ID!r}, got {package_id!r}"
        )
    if source != CRATES_IO_SOURCE:
        raise CheckFailure(f"locked cbor4ii package source must be {CRATES_IO_SOURCE!r}, got {source!r}")
    if version != "1.2.2":
        raise CheckFailure(f"locked cbor4ii package version must be 1.2.2, got {version!r}")
    nodes = [node for node in graph.get("resolve", {}).get("nodes", []) if node.get("id") == package_id]
    if len(nodes) != 1:
        raise CheckFailure(f"locked metadata must contain exactly one resolved node for {package_id!r}")
    resolved_features = set(nodes[0].get("features", []))
    required_features = {"serde", "serde1", "use_alloc"}
    if resolved_features != required_features:
        raise CheckFailure(
            f"locked cbor4ii node features must equal {sorted(required_features)}, got {sorted(resolved_features)}"
        )
    return package_id, source, version, resolved_features


def locked_graph(root: pathlib.Path, report: PolicyReport) -> None:
    _, _, members, _ = workspace_sets(root)
    crypto_member = "crates/crypto" in members
    if not crypto_member:
        subprocess.run(
            ["cargo", "test", "--workspace", "--all-targets", "--locked"],
            cwd=root,
            check=True,
        )
        print("SKIPPED unified serde1 evidence: telegraph-crypto is not a workspace member")
        print("PASS protocol-only workspace tests on the current graph")
        return
    if not (root / "Cargo.lock").is_file():
        raise CheckFailure("crypto is a workspace member but root Cargo.lock is missing")
    if len(report.crypto_serde_edges) != 1:
        raise CheckFailure("locked graph requires exactly one crypto cbor4ii serde1 requesting edge")
    package_id, source, version, resolved_features = validate_locked_metadata(_metadata_graph(root), report)
    print(
        "LOCKED cbor4ii package: "
        f"id={package_id} source={source} version={version} features={sorted(resolved_features)}"
    )
    subprocess.run(
        ["cargo", "test", "--workspace", "--all-targets", "--locked"],
        cwd=root,
        check=True,
    )
    print("PASS unified cbor4ii feature graph and workspace tests")


def _write(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def _assert_rejected(check, label: str, root: pathlib.Path) -> None:
    try:
        check()
        check_repository(root)
    except CheckFailure:
        return
    raise AssertionError(f"fixture unexpectedly passed: {label}")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="telegraph-c1-fixtures-") as directory:
        root = pathlib.Path(directory) / "fixture path with spaces"
        crypto = root / "crates/crypto"
        protocol = root / "crates/protocol"
        relay = root / "crates/relay"
        _write(
            root / "Cargo.toml",
            """
            [workspace]
            [workspace.dependencies]
            cbor4ii = "=1.2.2"
            provider = { package = "vodozemac", version = "=0.10.0" }
            """,
        )
        _write(
            crypto / "Cargo.toml",
            """
            [package]
            name = "telegraph-crypto"
            version = "0.1.0"
            [dependencies]
            cbor4ii = { workspace = true, optional = true, default-features = false, features = ["serde1"] }
            [features]
            pickle = ["cbor4ii?/serde1"]
            """,
        )
        _write(
            protocol / "Cargo.toml",
            """
            [package]
            name = "telegraph-protocol"
            version = "0.1.0"
            [dependencies]
            cbor4ii = { version = "=1.2.2", default-features = false }
            """,
        )
        _write(
            relay / "Cargo.toml",
            """
            [package]
            name = "telegraph-relay"
            version = "0.1.0"
            """,
        )
        _write(protocol / "src/lib.rs", "use cbor4ii::core::enc::Encode;\n")
        safe = r'''
            fn safe_fixture() {
                let normal = "cbor4ii::serde vodozemac::olm /* matrix-pickle */";
                let byte = b"cbor4ii::serde";
                let raw = r###"cbor4ii::serde /* nested */"###;
                let slash = '/';
                let lifetime = 'a;
                let serde = "ordinary identifier";
                fn lifetime<'serde>() {}
                let _ = (normal, byte, raw, slash, lifetime, serde);
            }
            /* outer cbor4ii::serde /* inner vodozemac */ still comment */
            // cbor4ii::serde vodozemac::olm
        '''
        for relative in (
            "src/lib.rs",
            "build.rs",
            "tests/case.rs",
            "examples/demo.rs",
            "benches/bench.rs",
        ):
            _write(relay / relative, safe)
        # include! is code, not data: a safe literal include and a nested
        # literal include must both be compiled/scanned recursively.
        _write(
            relay / "src/lib.rs",
            'include!("included.inc");\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn included_fixture_compiles() { super::included_fixture(); }\n}\n',
        )
        _write(relay / "src/included.inc", 'include!("nested.inc");\nfn included_fixture() { nested_fixture(); }\n')
        _write(relay / "src/nested.inc", "fn nested_fixture() {}\n")
        _write(relay / "target/ignored.rs", "use cbor4ii::serde;\n")
        report = check_repository(root)
        assert len(report.crypto_serde_edges) == 1
        nested_target = relay / "src/target/hidden.rs"
        _write(nested_target, "use cbor4ii::serde;\n")
        _assert_rejected(lambda: None, "nested src/target source", root)
        nested_target.unlink()
        fake = root / "crates/fake"
        _write(
            fake / "Cargo.toml",
            """
            [package]
            name = "telegraph-crypto"
            version = "0.1.0"
            [dependencies]
            codec = { package = "cbor4ii", version = "=1.2.2", features = ["serde1"] }
            """,
        )
        _assert_rejected(lambda: None, "crypto package-name masquerade", root)
        (fake / "Cargo.toml").unlink()
        fake.rmdir()
        original_protocol_manifest = protocol / "Cargo.toml"
        original_protocol_text = original_protocol_manifest.read_text(encoding="utf-8")
        original_protocol_manifest.write_text(
            original_protocol_text.replace("name = \"telegraph-protocol\"", "name = \"telegraph-fake\""),
            encoding="utf-8",
        )
        _assert_rejected(lambda: None, "protocol canonical-path masquerade", root)
        original_protocol_manifest.write_text(original_protocol_text, encoding="utf-8")
        crypto_manifest = crypto / "Cargo.toml"
        crypto_manifest_text = crypto_manifest.read_text(encoding="utf-8")
        crypto_manifest.unlink()
        assert not check_repository(root).crypto_serde_edges, "protocol-only no-crypto manifest handoff"
        crypto_manifest.write_text(crypto_manifest_text, encoding="utf-8")

        relay_manifest = relay / "Cargo.toml"
        protocol_manifest = protocol / "Cargo.toml"
        original_relay = relay_manifest.read_text(encoding="utf-8")
        original_protocol = protocol_manifest.read_text(encoding="utf-8")
        _assert_rejected(
            lambda: _write(
                relay_manifest,
                original_relay
                + """
                [target.'cfg(unix)'.dependencies]
                codec = { package = "cbor4ii", version = "=1.2.2" }
                """,
            ),
            "target cbor edge",
            root,
        )
        relay_manifest.write_text(original_relay, encoding="utf-8")

        # The crypto edge is a narrow exception: direct and forwarded feature
        # requests must never widen it to use_std or another provider feature.
        crypto_manifest = crypto / "Cargo.toml"
        original_crypto = crypto_manifest.read_text(encoding="utf-8")
        _assert_rejected(
            lambda: _write(
                crypto_manifest,
                original_crypto.replace('features = ["serde1"]', 'features = ["serde1", "use_std"]'),
            ),
            "crypto direct use_std feature",
            root,
        )
        crypto_manifest.write_text(original_crypto, encoding="utf-8")
        _assert_rejected(
            lambda: _write(
                crypto_manifest,
                original_crypto
                + "\n[features]\nforwarded-use-std = [\"cbor4ii/use_std\"]\n",
            ),
            "crypto forwarded use_std feature",
            root,
        )
        crypto_manifest.write_text(original_crypto, encoding="utf-8")
        _assert_rejected(
            lambda: _write(
                crypto_manifest,
                original_crypto.replace('features = ["serde1"]', 'features = ["serde1", "custom_extra_feature"]'),
            ),
            "crypto direct custom extra feature",
            root,
        )
        crypto_manifest.write_text(original_crypto, encoding="utf-8")
        _assert_rejected(
            lambda: _write(
                relay_manifest,
                original_relay
                + """
                [dev-dependencies]
                vp = { package = "vodozemac", version = "=0.10.0" }
                """,
            ),
            "dev provider edge",
            root,
        )
        relay_manifest.write_text(original_relay, encoding="utf-8")
        _assert_rejected(
            lambda: _write(
                relay_manifest,
                original_relay
                + """
                [build-dependencies]
                mp = { package = "matrix-pickle", version = "=0.2.3" }
                """,
            ),
            "build provider alias",
            root,
        )
        relay_manifest.write_text(original_relay, encoding="utf-8")
        _assert_rejected(
            lambda: _write(
                relay_manifest,
                original_relay
                + """
                [dependencies]
                sd = { package = "serde", version = "=1.0.0" }
                """,
            ),
            "non-crypto Serde provider edge",
            root,
        )
        relay_manifest.write_text(original_relay, encoding="utf-8")
        _assert_rejected(
            lambda: _write(
                relay_manifest,
                original_relay
                + """
                [dependencies]
                provider = { workspace = true }
                """,
            ),
            "workspace=true provider inference",
            root,
        )
        relay_manifest.write_text(original_relay, encoding="utf-8")
        _assert_rejected(
            lambda: _write(
                protocol_manifest,
                original_protocol.replace(
                    'cbor4ii = { version = "=1.2.2", default-features = false }',
                    'codec = { package = "cbor4ii", version = "=1.2.2", default-features = false }',
                ),
            ),
            "protocol cbor alias",
            root,
        )
        protocol_manifest.write_text(original_protocol, encoding="utf-8")
        _assert_rejected(
            lambda: _write(
                protocol_manifest,
                original_protocol
                + """
                [features]
                bad = ["cbor4ii?/serde1"]
                """,
            ),
            "non-crypto feature forwarding",
            root,
        )
        protocol_manifest.write_text(original_protocol, encoding="utf-8")

        source_path = relay / "tests/case.rs"
        original_source = source_path.read_text(encoding="utf-8")
        _assert_rejected(
            lambda: source_path.write_text("macro_rules! bad { () => { cbor4ii::serde }; }\n", encoding="utf-8"),
            "macro token source",
            root,
        )
        source_path.write_text(original_source, encoding="utf-8")
        _assert_rejected(
            lambda: source_path.write_text("extern crate vodozemac as provider;\n", encoding="utf-8"),
            "provider source inference",
            root,
        )
        source_path.write_text(original_source, encoding="utf-8")
        protocol_source = protocol / "src/lib.rs"
        original_protocol_source = protocol_source.read_text(encoding="utf-8")
        _assert_rejected(
            lambda: protocol_source.write_text("use cbor4ii::{core::enc::Encode};\n", encoding="utf-8"),
            "protocol non-core brace path",
            root,
        )
        protocol_source.write_text(original_protocol_source, encoding="utf-8")

        relay_source = relay / "src/lib.rs"
        original_relay_source = relay_source.read_text(encoding="utf-8")
        for label, dynamic_source in (
            ("dynamic concat include", 'include!(concat!("included", ".inc"));\n'),
            ("dynamic env include", 'include!(env!("TELEGRAPH_INCLUDED"));\n'),
            ("dynamic OUT_DIR include", 'include!(concat!(env!("OUT_DIR"), "/generated.inc"));\n'),
        ):
            _assert_rejected(
                lambda dynamic_source=dynamic_source: relay_source.write_text(dynamic_source, encoding="utf-8"),
                label,
                root,
            )
            relay_source.write_text(original_relay_source, encoding="utf-8")
        included_path = relay / "src/included.inc"
        original_included = included_path.read_text(encoding="utf-8")
        _assert_rejected(
            lambda: included_path.write_text('include!(env!("NESTED"));\n', encoding="utf-8"),
            "dynamic nested include",
            root,
        )
        included_path.write_text(original_included, encoding="utf-8")
        _assert_rejected(
            lambda: protocol_source.write_text("extern crate cbor4ii as codec;\n", encoding="utf-8"),
            "protocol extern alias",
            root,
        )
        protocol_source.write_text(original_protocol_source, encoding="utf-8")

        # Readiness fixtures only exercise metadata shape. The workflow keeps
        # the single inline readiness implementation and output writer.
        handoff = root / "Cargo.toml"
        _write(
            handoff,
            """
            [workspace]
            members = ["crates/protocol"]
            exclude = ["crates/crypto", "crates/store", "crates/relay", "crates/client", "crates/cli"]
            [workspace.metadata.telegraph]
            expected_crates = ["protocol", "crypto", "store", "relay", "client", "cli"]
            delivered_crates = ["protocol"]
            """,
        )
        expected, delivered, members, excluded = workspace_sets(root)
        assert delivered == {"crates/protocol"}
        assert members == delivered
        assert excluded == expected - delivered
        _write(
            handoff,
            handoff.read_text(encoding="utf-8").replace('delivered_crates = ["protocol"]', "delivered_crates = []"),
        )
        _, delivered, _, _ = workspace_sets(root)
        assert not delivered, "zero-delivered readiness fixture"
        _write(
            handoff,
            handoff.read_text(encoding="utf-8")
            .replace("delivered_crates = []", 'delivered_crates = ["protocol"]')
            .replace('members = ["crates/protocol"]', 'members = ["crates/protocol", "crates/extra"]'),
        )
        _, delivered, members, _ = workspace_sets(root)
        assert members != delivered, "extra-member readiness fixture"
    with tempfile.TemporaryDirectory(prefix="telegraph-c1-integrated-") as directory:
        root = pathlib.Path(directory) / "integrated workspace"
        _write(
            root / "Cargo.toml",
            """
            [workspace]
            resolver = "3"
            members = ["crates/protocol", "crates/crypto", "crates/relay"]
            exclude = ["crates/store", "crates/client", "crates/cli"]
            [workspace.metadata.telegraph]
            expected_crates = ["protocol", "crypto", "store", "relay", "client", "cli"]
            delivered_crates = ["protocol", "crypto", "relay"]
            """,
        )
        _write(
            root / "crates/protocol/Cargo.toml",
            """
            [package]
            name = "telegraph-protocol"
            version = "0.1.0"
            edition = "2024"
            [dependencies]
            cbor4ii = { version = "=1.2.2", default-features = false }
            """,
        )
        _write(
            root / "crates/protocol/src/lib.rs",
            """
            pub fn core_fixture() {}
            #[cfg(test)]
            mod tests {
                #[test]
                fn protocol_fixture_compiles() {
                    super::core_fixture();
                }
            }
            """,
        )
        _write(
            root / "crates/crypto/Cargo.toml",
            """
            [package]
            name = "telegraph-crypto"
            version = "0.1.0"
            edition = "2024"
            [dependencies]
            cbor4ii = { version = "=1.2.2", default-features = false, features = ["serde1"] }
            """,
        )
        _write(
            root / "crates/crypto/src/lib.rs",
            """
            pub fn crypto_fixture() {}
            #[cfg(test)]
            mod tests {
                #[test]
                fn crypto_fixture_compiles() {
                    super::crypto_fixture();
                }
            }
            """,
        )
        _write(
            root / "crates/relay/Cargo.toml",
            """
            [package]
            name = "telegraph-relay"
            version = "0.1.0"
            edition = "2024"
            """,
        )
        _write(
            root / "crates/relay/src/lib.rs",
            """
            include!("included.inc");
            #[cfg(test)]
            mod tests {
                #[test]
                fn included_fixture_compiles() { super::included_fixture(); }
            }
            """,
        )
        _write(root / "crates/relay/src/included.inc", 'include!("nested.inc");\nfn included_fixture() { nested_fixture(); }\n')
        _write(root / "crates/relay/src/nested.inc", "fn nested_fixture() {}\n")
        report = check_repository(root)
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, check=True, timeout=90)
        graph = _metadata_graph(root)
        validate_locked_metadata(graph, report)
        def assert_metadata_rejected(mutator, label: str) -> None:
            candidate = copy.deepcopy(graph)
            mutator(candidate)
            try:
                validate_locked_metadata(candidate, report)
            except CheckFailure:
                return
            raise AssertionError(f"metadata fixture unexpectedly passed: {label}")

        cbor_package = next(package for package in graph["packages"] if package["name"] == CBOR_PACKAGE)
        def cbor_package_set(candidate, key: str, value: str) -> None:
            next(package for package in candidate["packages"] if package["name"] == CBOR_PACKAGE)[key] = value

        assert_metadata_rejected(
            lambda candidate: cbor_package_set(candidate, "version", "1.2.3"),
            "metadata version mismatch",
        )
        assert_metadata_rejected(
            lambda candidate: cbor_package_set(candidate, "source", "registry+https://evil.invalid/index"),
            "metadata source mismatch",
        )
        assert_metadata_rejected(
            lambda candidate: candidate["packages"].append(copy.deepcopy(cbor_package)),
            "duplicate metadata package ID",
        )
        assert_metadata_rejected(
            lambda candidate: candidate["resolve"]["nodes"][
                next(i for i, node in enumerate(candidate["resolve"]["nodes"]) if node["id"] == cbor_package["id"])
            ].update({"id": cbor_package["id"] + "-mismatch"}),
            "resolved node ID mismatch",
        )
        def synchronously_tamper_package_and_node(candidate: dict) -> None:
            package = next(item for item in candidate["packages"] if item["name"] == CBOR_PACKAGE)
            original_id = package["id"]
            tampered_id = original_id + "-tampered"
            package["id"] = tampered_id
            node = next(item for item in candidate["resolve"]["nodes"] if item["id"] == original_id)
            node["id"] = tampered_id

        assert_metadata_rejected(
            synchronously_tamper_package_and_node,
            "package and resolved node IDs synchronously tampered",
        )
        assert_metadata_rejected(
            lambda candidate: candidate["resolve"]["nodes"][
                next(i for i, node in enumerate(candidate["resolve"]["nodes"]) if node["id"] == cbor_package["id"])
            ]["features"].remove("use_alloc"),
            "resolved feature mismatch",
        )
        integrated_protocol_manifest = root / "crates/protocol/Cargo.toml"
        integrated_protocol_text = integrated_protocol_manifest.read_text(encoding="utf-8")
        integrated_protocol_manifest.write_text(
            integrated_protocol_text.replace('version = "=1.2.2"', 'version = "1.2.2"'),
            encoding="utf-8",
        )
        _assert_rejected(lambda: None, "manifest wide cbor version", root)
        integrated_protocol_manifest.write_text(integrated_protocol_text, encoding="utf-8")
        locked_graph(root, report)
    print("PASS C1 manifest, feature-forwarding, lexical-source, locked-shape, and readiness fixtures")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd())
    parser.add_argument("--locked-graph", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    root = args.root.resolve()
    try:
        report = check_repository(root)
        print(
            "PASS ADR0005 C1 source/manifest policy: "
            f"checked {len(report.crates)} existing crate manifests; "
            f"crypto serde1 requests={len(report.crypto_serde_edges)}"
        )
        if args.locked_graph:
            locked_graph(root, report)
        return 0
    except (CheckFailure, subprocess.CalledProcessError) as exc:
        print(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
