#!/usr/bin/env python3
"""One-off: copy sudoRmGuard data from ~/.claude/hooks into a z-agent-guard config dir.

    tools/migrate.py [--from ~/.claude/hooks] [--to <config dir>] [--dry-run]

--to defaults to the dir the guard would use (see zag/config.py). Copies, never moves:
the old files stay until you delete them. Refuses to overwrite an existing rules.json.

- sudoRmGuard-rules.json      -> rules.json   ("hosts" moves to config.json)
- sudoRmGuard-rules.d/*.json  -> rules.d/
- sudoRmGuard-rules.archive.json / .recovery.json -> rules.archive.json / rules.recovery.json
- deny rules: the literal home dir becomes {home}, so they work on other machines
"""
import argparse
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from zag import config  # noqa: E402

HOME = os.path.expanduser("~")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src", default=os.path.join(HOME, ".claude", "hooks"))
    ap.add_argument("--to", dest="dst", default=config.CONFIG_DIR)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    src, dst = args.src, args.dst
    old = lambda name: os.path.join(src, "sudoRmGuard-" + name)  # noqa: E731

    with open(old("rules.json")) as f:
        data = json.load(f)
    if os.path.exists(os.path.join(dst, "rules.json")):
        sys.exit(f"{dst}/rules.json already exists; not overwriting")

    hosts = data.pop("hosts", {}) or {}
    changed = 0

    def generalize(rules):
        nonlocal changed
        for r in rules:
            if r.get("decision") == "deny" and HOME in r.get("match", ""):
                r["match"] = r["match"].replace(HOME, "{home}")
                changed += 1
        return rules

    generalize(data.get("rules", []))
    folder = {}
    if os.path.isdir(old("rules.d")):
        for name in sorted(os.listdir(old("rules.d"))):
            if name.endswith(".json"):
                with open(os.path.join(old("rules.d"), name)) as f:
                    part = json.load(f)
                generalize(part.get("rules", []))
                folder[name] = part

    cfgPath = os.path.join(dst, "config.json")
    cfg = {}
    if os.path.exists(cfgPath):
        with open(cfgPath) as f:
            cfg = json.load(f)
    if hosts:
        cfg["hosts"] = {**hosts, **cfg.get("hosts", {})}

    print(f"to {dst}:")
    print(f"  rules.json: {len(data.get('rules', []))} rules, {len(data.get('pending', []))} pending, "
          f"{len(data.get('grants', {}))} session grants")
    for name, part in folder.items():
        print(f"  rules.d/{name}: {len(part.get('rules', []))} rules")
    for name in ("rules.archive.json", "rules.recovery.json"):
        if os.path.exists(old(name)):
            print(f"  {name}")
    print(f"  config.json: {len(cfg.get('hosts', {}))} host aliases")
    print(f"  deny rules generalized to {{home}}: {changed}")
    if args.dry_run:
        return

    os.makedirs(os.path.join(dst, "rules.d"), exist_ok=True)

    def write(path, obj):
        with open(path, "w") as f:
            f.write(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")

    write(os.path.join(dst, "rules.json"), data)
    for name, part in folder.items():
        write(os.path.join(dst, "rules.d", name), part)
    for name in ("rules.archive.json", "rules.recovery.json"):
        if os.path.exists(old(name)):
            shutil.copy2(old(name), os.path.join(dst, name))
    if cfg:
        write(cfgPath, cfg)
    print("done")


if __name__ == "__main__":
    main()
