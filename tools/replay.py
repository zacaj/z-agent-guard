#!/usr/bin/env python3
"""Replay Bash commands from Claude Code transcripts through the guard's decide().

Writes one JSON line per unique (command, cwd) with the decision and reason, so two
versions of the guard can be compared:

    tools/replay.py --guard old/sudoRmGuard.py --rules snapshot.json > old.jsonl
    tools/replay.py --guard . --rules snapshot.json > new.jsonl
    tools/compare.py old.jsonl new.jsonl

Nothing is written to the rules files: decide() gets the rules data directly and the
archive path is pointed at a missing file. Exceptions are reported as decision "ERROR".
"""
import argparse
import glob
import importlib.util
import json
import os
import sys


def loadGuard(path):
    """A single-file guard (old layout), or a checkout containing the zag package."""
    path = os.path.abspath(path)
    if os.path.isdir(os.path.join(path, "zag")):
        sys.path.insert(0, path)
        import zag.hook
        import zag.storage
        zag.hook.validateRules = zag.storage.validateRules
        return zag.hook, [zag.hook, zag.storage]
    spec = importlib.util.spec_from_file_location("guard_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.dirname(path))
    spec.loader.exec_module(mod)
    return mod, [mod]


def commands(projectsDir):
    """(command, cwd, session) for every Bash tool call, deduplicated."""
    seen = set()
    for f in sorted(glob.glob(os.path.join(projectsDir, "**", "*.jsonl"), recursive=True)):
        try:
            fh = open(f, errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                if '"Bash"' not in line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                content = (d.get("message") or {}).get("content")
                if not isinstance(content, list):
                    continue
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == "Bash":
                        cmd = (b.get("input") or {}).get("command")
                        key = (cmd, d.get("cwd"))
                        if isinstance(cmd, str) and key not in seen:
                            seen.add(key)
                            yield cmd, d.get("cwd"), d.get("sessionId", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--guard", required=True, help="old single-file guard, or a checkout dir with zag/")
    ap.add_argument("--rules", required=True, help="rules JSON snapshot (with rules.d merged in)")
    ap.add_argument("--projects", default=os.path.expanduser("~/.claude/projects"))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    g, mods = loadGuard(args.guard)
    for m in mods:
        m.ARCHIVE_PATH = "/nonexistent/archive.json"
    with open(args.rules) as f:
        data = json.load(f)
    validate = getattr(g, "validateRules")
    data = validate(data)

    n = errors = 0
    for cmd, cwd, session in commands(args.projects):
        try:
            d, reason, _ = g.decide(cmd, cwd, session, json.loads(json.dumps(data)))
        except Exception as e:
            d, reason = "ERROR", f"{type(e).__name__}: {e}"
            errors += 1
        print(json.dumps({"cmd": cmd, "cwd": cwd, "decision": d, "reason": reason}))
        n += 1
        if args.limit and n >= args.limit:
            break
    print(f"replayed {n} commands, {errors} errors", file=sys.stderr)


if __name__ == "__main__":
    main()
