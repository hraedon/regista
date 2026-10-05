"""Mechanically compare root bindings and complete parser paths at 84bb2ec and HEAD.

No historical dependencies are imported. Parser construction is interpreted from
AST, including chained add_parser/add_subparsers calls. Incidental implementation
bindings are preserved separately from deliberately re-exported API names.
"""
from __future__ import annotations

import argparse
import ast
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
REFERENCE = "84bb2ec"
OUTPUT = ROOT / "docs/breaking-0.8-inventory.json"


def old_file(name: str) -> str:
    return subprocess.check_output(["git", "show", f"{REFERENCE}:{name}"],
                                   cwd=ROOT, text=True)


def root_bindings(source: str, *, historical: bool) -> tuple[list[str], list[str]]:
    tree = ast.parse(source)
    bound: set[str] = set()
    public: set[str] = set()
    deliberate = {"ErrorCode", "RegistaError", "ConnectionInfo", "Event", "REGISTA_VERSION"}
    for node in tree.body:
        if isinstance(node, (ast.ImportFrom, ast.Import)):
            for name in node.names:
                binding = name.asname or name.name.split(".")[0]
                bound.add(binding)
                if name.asname == name.name or binding in deliberate:
                    public.add(binding)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
            if not node.name.startswith("_"):
                public.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bound.add(target.id)
                    if target.id == "config":
                        public.add(target.id)
                    if not historical and target.id == "__all__":
                        public = set(ast.literal_eval(node.value))
    if not historical:
        # Explicit __all__ is the normative current surface.
        assignment = next(n for n in tree.body if isinstance(n, ast.Assign) and
                          any(isinstance(t, ast.Name) and t.id == "__all__" for t in n.targets))
        public = set(ast.literal_eval(assignment.value))
    return sorted(n for n in public if not n.startswith("_")), sorted(bound - public)


def command_paths(source: str) -> list[str]:
    tree = ast.parse(source)
    paths: set[tuple[str, ...]] = set()
    variables: dict[str, tuple[str, ...]] = {}

    def evaluate(node: ast.expr) -> tuple[str, ...] | None:
        if isinstance(node, ast.Name):
            return variables.get(node.id)
        if not isinstance(node, ast.Call):
            return None
        if isinstance(node.func, ast.Name) and node.func.id == "_RefusalParser":
            return ()
        if not isinstance(node.func, ast.Attribute):
            return None
        if node.func.attr == "ArgumentParser" or node.func.attr == "_RefusalParser":
            return ()
        parent = evaluate(node.func.value)
        if parent is None:
            return None
        if node.func.attr == "add_subparsers":
            return parent
        if node.func.attr == "add_parser":
            name = ast.literal_eval(node.args[0])
            assert isinstance(name, str)
            path = (*parent, name)
            paths.add(path)
            return path
        return None

    # Walk construction statements in source order; calls inside helpers only
    # configure common flags and cannot manufacture undocumented command paths.
    for node in sorted(ast.walk(tree), key=lambda n: getattr(n, "lineno", 0)):
        if isinstance(node, ast.Assign):
            value = evaluate(node.value)
            if value is not None:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        variables[target.id] = value
        elif isinstance(node, ast.Expr):
            evaluate(node.value)
    return sorted(" ".join(path) for path in paths)


def inventory() -> dict[str, Any]:
    old, internals = root_bindings(old_file("src/regista/__init__.py"), historical=True)
    new, current_internal = root_bindings((ROOT / "src/regista/__init__.py").read_text(),
                                          historical=False)
    old_paths = command_paths(old_file("src/regista/_cli.py"))
    new_paths = command_paths((ROOT / "src/regista/cli.py").read_text())
    return {
        "reference": REFERENCE,
        "old_public": old, "new_public": new,
        "removed_public": sorted(set(old) - set(new)),
        "added_public": sorted(set(new) - set(old)),
        "retained_names_changed_contract": sorted(set(old) & set(new)),
        "old_implementation_bindings": internals,
        "new_implementation_bindings": current_internal,
        "old_commands": old_paths, "new_commands": new_paths,
        "removed_commands": sorted(set(old_paths) - set(new_paths)),
        "added_commands": sorted(set(new_paths) - set(old_paths)),
        "retained_commands_changed_contract": sorted(set(new_paths) & set(old_paths)),
    }


def render(data: dict[str, Any]) -> str:
    lines = ["## Mechanically generated 0.7.2 → 0.8.0 inventory", "",
             "Generated from `84bb2ec:src/regista/__init__.py`, its complete CLI parser",
             "and the current root/parser by `scripts/generate_removal_inventory.py`.",
             "The [complete machine-readable comparison](breaking-0.8-inventory.json)",
             "also lists every added name/path. Retained spelling does not preserve the",
             "old contract.",
             "", "### Old public root names", "", "| Name | 0.8.0 disposition |", "| --- | --- |"]
    for name in data["old_public"]:
        status = ("retained name; changed kernel contract"
                  if name in data["new_public"] else "removed")
        lines.append(f"| `{name}` | {status} |")
    lines.extend(["", "### Old full command tree", "", "| Full path | 0.8.0 disposition |",
                  "| --- | --- |"])
    for path in data["old_commands"]:
        status = ("retained spelling; changed kernel format/contract"
                  if path in data["new_commands"] else "removed")
        lines.append(f"| `{path}` | {status} |")
    lines.extend(["", "### Intentional implementation bindings", "",
                  "These bindings in the old root implement the facade or support imports;",
                  "they are not deliberate API re-exports. Underscore names are private.",
                  "They are tracked separately, including `_config`; its public alias `config`",
                  "appears in the API table above.", "",
                  ", ".join(f"`{name}`" for name in data["old_implementation_bindings"]), ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = inventory()
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    doc_path = ROOT / "docs/breaking-0.8.md"
    old = doc_path.read_text()
    prefix = old.split("## Explicit removed", 1)[0].split(
        "## Mechanically generated 0.7.2", 1)[0]
    text = prefix.rstrip() + "\n\n" + render(data)
    if args.check:
        if OUTPUT.read_text() != encoded or doc_path.read_text() != text:
            raise SystemExit("removal inventory differs; regenerate it")
    else:
        OUTPUT.write_text(encoded)
        doc_path.write_text(text)


if __name__ == "__main__":
    main()
