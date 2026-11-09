#!/usr/bin/env python3
"""Compare two replay.py outputs by (command, cwd): tools/compare.py old.jsonl new.jsonl"""
import json, sys
def load(f): return {(d["cmd"], d["cwd"]): (d["decision"], d["reason"]) for d in map(json.loads, open(f))}
a, b = load(sys.argv[1]), load(sys.argv[2])
common = a.keys() & b.keys()
diffs = [k for k in common if a[k] != b[k]]
print(f"common {len(common)}, only-a {len(a.keys()-b.keys())}, only-b {len(b.keys()-a.keys())}, differing {len(diffs)}")
for k in diffs[:5]: print(k[0][:80], a[k], b[k])
