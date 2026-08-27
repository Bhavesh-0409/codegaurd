"""
Deterministic import extraction.

IMPORTANT: This step must NOT use an LLM. The whole point of Sentinel is that
we don't trust an LLM's own claims about what packages exist or were imported -
that's the same failure mode (hallucination) we're defending against. So we
parse imports with Python's real `ast` module and hand a ground-truth list of
{package, line_number} to the agent, which then must verify each one with tools.
"""

import ast
from dataclasses import dataclass


@dataclass
class ImportRef:
    package: str        # top-level package name, e.g. "requests"
    full_statement: str  # the raw import line, for display
    line_number: int


def extract_python_imports(source_code: str) -> list[ImportRef]:
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        raise ValueError(f"Could not parse code: {e}")

    imports: list[ImportRef] = []
    lines = source_code.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level = alias.name.split(".")[0]
                imports.append(
                    ImportRef(
                        package=top_level,
                        full_statement=lines[node.lineno - 1].strip(),
                        line_number=node.lineno,
                    )
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:  # skip relative imports (. / ..)
                top_level = node.module.split(".")[0]
                imports.append(
                    ImportRef(
                        package=top_level,
                        full_statement=lines[node.lineno - 1].strip(),
                        line_number=node.lineno,
                    )
                )

    # de-dupe while preserving first-seen line number
    seen = {}
    for imp in imports:
        if imp.package not in seen:
            seen[imp.package] = imp
    return list(seen.values())


# Standard library modules should never be checked against PyPI - filter these out.
STDLIB_MODULES = {
    "os", "sys", "re", "json", "math", "random", "datetime", "time", "collections",
    "itertools", "functools", "typing", "pathlib", "subprocess", "threading",
    "asyncio", "logging", "unittest", "sqlite3", "csv", "io", "abc", "copy",
    "dataclasses", "enum", "contextlib", "hashlib", "base64", "argparse", "shutil",
    "socket", "struct", "traceback", "uuid", "warnings", "xml", "html", "http",
    "urllib", "string", "textwrap", "queue", "pickle", "operator", "inspect",
}


def filter_third_party(imports: list[ImportRef]) -> list[ImportRef]:
    return [i for i in imports if i.package.lower() not in STDLIB_MODULES]
