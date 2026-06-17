"""
Call Graph Analyser — Phase 5
Builds per-language call graphs from repository source code and answers
reachability questions: "is this crypto finding called from an entry point?"

Supported languages:
  Python  — ast module (full AST walk, decorator-based entry detection)
  Go      — regex parse of .go source files
  Java    — javap -p on .class files + regex parse of .java source files

Entry points detected per language:
  Python: main(), if __name__=="__main__", @app.route/get/post, @celery.task, test_*
  Go    : func main(), http.HandleFunc/router.GET registrations, Test* functions
  Java  : public static void main, @GetMapping/@PostMapping, doGet/doPost, @Test
"""

import ast
import os
import re
import json
import logging
import subprocess
import warnings
from collections import deque
from typing import Optional

logger = logging.getLogger(__name__)

MAX_FILE_SIZE  = 300_000   # skip files > 300 KB to bound analysis time
MAX_FILES      = 500       # cap total files analysed per language
MAX_CHAIN_DEPTH = 50       # truncate call chains beyond this depth
ANALYSIS_TIMEOUT = 60     # seconds per subprocess call

# ─── Core data structure ──────────────────────────────────────────────────────

class CallGraph:
    """
    Directed graph of function-call relationships.
    Node IDs are strings of the form  "rel/path/to/file.ext::FunctionName"
    or just a bare "FunctionName" for unresolved cross-file calls.
    """
    def __init__(self):
        self.edges:        dict[str, set[str]]          = {}
        self.entry_points: set[str]                     = set()
        # func_id -> (rel_file_path, start_line, end_line)
        self.func_spans:   dict[str, tuple[str,int,int]] = {}
        # bare name -> [func_ids]  — for cross-file resolution
        self._bare_index:  dict[str, list[str]]          = {}

    # ── Mutation helpers ──────────────────────────────────────────────────────

    def register_func(self, func_id: str, rel_path: str, start: int, end: int):
        self.func_spans[func_id] = (rel_path, start, end)
        # Strip @lineno suffix (added for uniqueness) so bare-name cross-file
        # resolution still works — e.g. "src/a.py::foo@10" → bare = "foo"
        bare = func_id.split("::")[-1].split("@")[0]
        self._bare_index.setdefault(bare, []).append(func_id)

    def add_call(self, caller: str, callee: str):
        self.edges.setdefault(caller, set()).add(callee)

    def add_entry(self, func_id: str):
        self.entry_points.add(func_id)

    # ── Query helpers ─────────────────────────────────────────────────────────

    def find_function_at(self, rel_path: str, line_number: int) -> Optional[str]:
        """Return the tightest function span that contains rel_path:line_number."""
        best: Optional[str] = None
        best_size: Optional[int] = None
        for fid, (fp, start, end) in self.func_spans.items():
            if fp == rel_path and start <= line_number <= end:
                size = end - start
                if best_size is None or size < best_size:
                    best, best_size = fid, size
        return best

    # ── BFS reachability ──────────────────────────────────────────────────────

    def bfs(self) -> dict[str, tuple[int, list[str]]]:
        """
        BFS from all registered entry points.
        Returns {func_id: (depth, call_chain_names)} for every reachable node.
        call_chain_names is a list of bare function names from entry → callee.
        """
        visited: dict[str, tuple[int, list[str]]] = {}
        queue:   deque[str]                        = deque()

        for ep in self.entry_points:
            bare = ep.split("::")[-1]
            visited[ep] = (0, [bare])
            queue.append(ep)

        while queue:
            current = queue.popleft()
            depth, chain = visited[current]

            for raw_callee in self.edges.get(current, set()):
                # Try exact match first
                candidates = [raw_callee] if raw_callee in self.func_spans else []

                # If no exact match, resolve via bare-name index
                if not candidates:
                    bare = raw_callee.split("::")[-1]
                    candidates = self._bare_index.get(bare, [])

                for callee in candidates:
                    if callee not in visited:
                        bare_callee = callee.split("::")[-1]
                        new_chain = (chain + [bare_callee])[-MAX_CHAIN_DEPTH:]
                        visited[callee] = (depth + 1, new_chain)
                        queue.append(callee)

        return visited


# ─── Python AST builder ───────────────────────────────────────────────────────

# Decorator substrings that mark entry-point functions
_PY_ENTRY_DECS = {
    "route", "get", "post", "put", "delete", "patch", "head", "options",
    "task", "on_event", "command", "handle", "handler", "on",
    "scheduled", "periodic", "cron",
}

def _build_python(repo_path: str, cg: CallGraph) -> None:
    count = 0
    for root, _, files in os.walk(repo_path):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            full_path = os.path.join(root, fname)
            if os.path.getsize(full_path) > MAX_FILE_SIZE:
                continue
            rel_path = os.path.relpath(full_path, repo_path)
            try:
                _analyze_python_file(full_path, rel_path, cg)
            except Exception as e:
                logger.debug("Python AST skip %s: %s", rel_path, e)
            count += 1
            if count >= MAX_FILES:
                return


def _analyze_python_file(full_path: str, rel_path: str, cg: CallGraph) -> None:
    with open(full_path, encoding="utf-8", errors="ignore") as fh:
        source = fh.read()

    # Suppress SyntaxWarnings (e.g. invalid escape sequences like r"\." in
    # string literals) — these are cosmetic issues in user code, not ours.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source, filename=full_path)

    # ── Pass 1: register all function spans + entry points ───────────────────
    func_nodes: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Include start line in func_id to avoid collisions when multiple
        # functions/methods share the same name in one file (e.g. __init__
        # in ClassA vs ClassB) — without this the second overwrites the
        # first in func_spans and findings in the first are never located.
        func_id  = f"{rel_path}::{node.name}@{node.lineno}"
        end_line = getattr(node, "end_lineno", node.lineno + 1)
        cg.register_func(func_id, rel_path, node.lineno, end_line)
        func_nodes.append((func_id, node))

        # Entry-point detection
        if node.name == "main":
            cg.add_entry(func_id)

        if node.name.startswith("test_") or node.name.startswith("Test"):
            cg.add_entry(func_id)

        for dec in node.decorator_list:
            dec_name = _py_dec_name(dec).lower()
            if any(s in dec_name for s in _PY_ENTRY_DECS):
                cg.add_entry(func_id)
                break

    # ── if __name__ == "__main__": block ──────────────────────────────────────
    main_block_id = f"{rel_path}::__main__"
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        t = node.test
        if (isinstance(t, ast.Compare)
                and isinstance(t.left, ast.Name) and t.left.id == "__name__"
                and any(isinstance(c, ast.Constant) and c.value == "__main__"
                        for c in t.comparators)):
            end_line = getattr(node, "end_lineno", node.lineno + 50)
            cg.register_func(main_block_id, rel_path, node.lineno, end_line)
            cg.add_entry(main_block_id)
            # Treat direct calls inside the block as children
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    callee = _py_call_name(child)
                    if callee:
                        cg.add_call(main_block_id, f"{rel_path}::{callee}")
                        cg.add_call(main_block_id, callee)

    # ── Pass 2: extract function calls within each function ───────────────────
    for func_id, func_node in func_nodes:
        for child in ast.walk(func_node):
            if isinstance(child, ast.Call):
                callee = _py_call_name(child)
                if callee:
                    cg.add_call(func_id, f"{rel_path}::{callee}")  # intra-file
                    cg.add_call(func_id, callee)                   # bare (inter-file)


def _py_dec_name(dec) -> str:
    if isinstance(dec, ast.Name):      return dec.id
    if isinstance(dec, ast.Attribute): return dec.attr
    if isinstance(dec, ast.Call):      return _py_dec_name(dec.func)
    return ""


def _py_call_name(node: ast.Call) -> Optional[str]:
    if isinstance(node.func, ast.Name):      return node.func.id
    if isinstance(node.func, ast.Attribute): return node.func.attr
    return None


# ─── Go regex builder ─────────────────────────────────────────────────────────

_GO_FUNC_DEF   = re.compile(r'^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(', re.M)
_GO_FUNC_CALL  = re.compile(r'\b(\w+)\s*\(')
_GO_ENTRY_DECS = re.compile(
    r'HandleFunc|Handle\b|GET|POST|PUT|DELETE|PATCH|HandlerFunc|ServeHTTP'
    r'|Register|Route\b|Run\b|Serve\b'
)

def _build_go(repo_path: str, cg: CallGraph) -> None:
    count = 0
    for root, _, files in os.walk(repo_path):
        for fname in files:
            if not fname.endswith(".go"):
                continue
            full_path = os.path.join(root, fname)
            if os.path.getsize(full_path) > MAX_FILE_SIZE:
                continue
            rel_path = os.path.relpath(full_path, repo_path)
            try:
                _analyze_go_file(full_path, rel_path, cg)
            except Exception as e:
                logger.debug("Go skip %s: %s", rel_path, e)
            count += 1
            if count >= MAX_FILES:
                return


def _analyze_go_file(full_path: str, rel_path: str, cg: CallGraph) -> None:
    with open(full_path, encoding="utf-8", errors="ignore") as fh:
        source = fh.read()

    lines = source.splitlines()

    # Find all function definitions with line ranges
    func_defs: list[tuple[str, int]] = []  # (name, start_line)
    for m in _GO_FUNC_DEF.finditer(source):
        name       = m.group(1)
        start_line = source[:m.start()].count("\n") + 1
        func_defs.append((name, start_line))

    # Assign end lines (next func start - 1 or EOF)
    for i, (name, start_line) in enumerate(func_defs):
        end_line = func_defs[i+1][1] - 1 if i + 1 < len(func_defs) else len(lines)
        func_id  = f"{rel_path}::{name}@{start_line}"
        cg.register_func(func_id, rel_path, start_line, end_line)

        # Entry points
        if name == "main":
            cg.add_entry(func_id)
        if name.startswith("Test"):
            cg.add_entry(func_id)

    # Extract calls within each function's line range
    for i, (name, start_line) in enumerate(func_defs):
        end_line  = func_defs[i+1][1] - 1 if i + 1 < len(func_defs) else len(lines)
        func_id   = f"{rel_path}::{name}@{start_line}"
        body      = "\n".join(lines[start_line:end_line])

        for cm in _GO_FUNC_CALL.finditer(body):
            callee = cm.group(1)
            if callee and callee[0].isupper() or callee in {"main"}:
                cg.add_call(func_id, callee)

        # Register HTTP handler registrations as entry-point wires.
        # Use bare name so _bare_index lookup picks up all matching funcs.
        if _GO_ENTRY_DECS.search(body):
            for cm in _GO_FUNC_CALL.finditer(body):
                callee = cm.group(1)
                if callee and callee[0].isupper():
                    for fid in cg._bare_index.get(callee, [callee]):
                        cg.add_entry(fid)


# ─── Java builder (javap + .java regex) ──────────────────────────────────────

_JAVA_METHOD     = re.compile(
    r'^\s*(?:public|private|protected)?\s*(?:static\s+)?[\w<>\[\]]+\s+(\w+)\s*\(', re.M)
_JAVA_CALL       = re.compile(r'\b(\w+)\s*\(')
_JAVAP_METHOD    = re.compile(r'^\s+\S.+?(\w+)\(', re.M)
_JAVA_ENTRY_ANN  = re.compile(
    r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping'
    r'|@Test\b|@Before\b|@After\b'
    r'|@Scheduled\b|@EventListener\b'
)


def _build_java(repo_path: str, cg: CallGraph) -> None:
    count = 0
    for root, _, files in os.walk(repo_path):
        for fname in files:
            if not fname.endswith((".java", ".class")):
                continue                        # only count Java/class files
            full_path = os.path.join(root, fname)
            if os.path.getsize(full_path) > MAX_FILE_SIZE:
                continue
            rel_path = os.path.relpath(full_path, repo_path)
            try:
                if fname.endswith(".java"):
                    _analyze_java_source(full_path, rel_path, cg)
                else:
                    _analyze_java_class(full_path, rel_path, cg)
            except Exception as e:
                logger.debug("Java skip %s: %s", rel_path, e)
            count += 1
            if count >= MAX_FILES:
                return


def _analyze_java_source(full_path: str, rel_path: str, cg: CallGraph) -> None:
    with open(full_path, encoding="utf-8", errors="ignore") as fh:
        source = fh.read()

    lines = source.splitlines()
    methods: list[tuple[str, int]] = []

    for m in _JAVA_METHOD.finditer(source):
        name       = m.group(1)
        start_line = source[:m.start()].count("\n") + 1
        methods.append((name, start_line))

    for i, (name, start_line) in enumerate(methods):
        end_line = methods[i+1][1] - 1 if i + 1 < len(methods) else len(lines)
        func_id  = f"{rel_path}::{name}@{start_line}"
        cg.register_func(func_id, rel_path, start_line, end_line)

        # Entry points
        if name == "main":
            cg.add_entry(func_id)
        if name in ("doGet", "doPost", "service", "init", "destroy"):
            cg.add_entry(func_id)

        # Lines before method for annotations
        ann_block = "\n".join(lines[max(0, start_line - 4):start_line])
        if _JAVA_ENTRY_ANN.search(ann_block):
            cg.add_entry(func_id)

        # Extract calls
        body = "\n".join(lines[start_line:end_line])
        for cm in _JAVA_CALL.finditer(body):
            callee = cm.group(1)
            if callee and not callee[0].isdigit():
                cg.add_call(func_id, f"{rel_path}::{callee}")
                cg.add_call(func_id, callee)


def _analyze_java_class(full_path: str, rel_path: str, cg: CallGraph) -> None:
    """Use javap -p to disassemble .class and extract method signatures."""
    try:
        result = subprocess.run(
            ["javap", "-p", full_path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return
    except Exception:
        return

    for m in _JAVAP_METHOD.finditer(result.stdout):
        name    = m.group(1)
        func_id = f"{rel_path}::{name}"
        # We don't have line numbers from javap -p alone — use line 0
        cg.register_func(func_id, rel_path, 0, 0)
        if name in ("main", "doGet", "doPost", "service"):
            cg.add_entry(func_id)


# ─── Top-level analysis function ─────────────────────────────────────────────

def analyze_repo_call_graph(
    repo_path: str,
    findings: list,   # list of (finding_id, rel_file_path, line_number, source_type)
) -> dict[str, tuple[bool, Optional[int], list[str]]]:
    """
    Build a multi-language call graph for `repo_path` and return reachability
    information for each finding.

    Returns:
        {finding_id: (reachable, depth_or_None, call_chain_names)}
    """
    cg = CallGraph()

    # Single walk to detect which languages are present
    has_py = has_go = has_java = False
    for _, _dirs, _files in os.walk(repo_path):
        for f in _files:
            if f.endswith(".py"):                  has_py   = True
            if f.endswith(".go"):                  has_go   = True
            if f.endswith((".java", ".class")):    has_java = True
        if has_py and has_go and has_java:
            break  # all languages found; stop early

    if has_py:
        logger.info("Building Python call graph for %s", repo_path)
        try:
            _build_python(repo_path, cg)
        except Exception as e:
            logger.warning("Python call graph error: %s", e)

    if has_go:
        logger.info("Building Go call graph for %s", repo_path)
        try:
            _build_go(repo_path, cg)
        except Exception as e:
            logger.warning("Go call graph error: %s", e)

    if has_java:
        logger.info("Building Java call graph for %s", repo_path)
        try:
            _build_java(repo_path, cg)
        except Exception as e:
            logger.warning("Java call graph error: %s", e)

    if not cg.entry_points:
        logger.info("No entry points found — skipping reachability analysis")
        return {}

    logger.info("BFS from %d entry points, graph has %d nodes",
                len(cg.entry_points), len(cg.func_spans))

    reachability = cg.bfs()

    results: dict[str, tuple[bool, Optional[int], list[str]]] = {}
    for finding_id, rel_file_path, line_number, source_type in findings:
        # Only analyse source-code findings (not deps/artifacts which have no call site)
        if source_type not in ("source_code", None):
            continue

        func_id = cg.find_function_at(rel_file_path, line_number)
        if func_id is None:
            # Finding is at module/class scope — not inside any function body.
            # Module-level code executes unconditionally at import time, so it
            # IS reachable from any entry point that imports the module.
            # Marking it unreachable would produce many false "dead code" flags.
            results[finding_id] = (True, 0, ["<module-level>"])
            continue

        if func_id in reachability:
            depth, chain = reachability[func_id]
            results[finding_id] = (True, depth, chain)
        else:
            results[finding_id] = (False, None, [])

    return results
