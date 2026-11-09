"""z-agent-guard: storage (moved verbatim from the single-file hook)."""
import fcntl
import json
import os
import re
import time

from .defaults import ARCHIVED_SESSION_IDLE_DAYS, ARCHIVE_IDLE_DAYS, ARCHIVE_MAX_USES, HOME, MAINT_INTERVAL, PENDING_MAX, PENDING_TTL, RULE_KEY_ORDER, SPLIT_MIN
from .util import nowText, sha
from .rules import HOST_ALIASES, containerMatches, ruleIdentity, textMatches


HOOK_DIR = os.path.join(HOME, ".claude", "hooks")
RULES_PATH = os.path.join(HOOK_DIR, "sudoRmGuard-rules.json")


def recordUsage(used):
    """Stamp lastUsed and bump uses on the rules that decided this call. Fields only
    appear once a rule is used after being created."""
    if not used:
        return
    ids = {}
    for r in used:
        ids[ruleIdentity(r)] = ids.get(ruleIdentity(r), 0) + 1
    with Lock():
        try:
            rules = loadRules()
        except RulesFileError:
            return
        changed = False
        for r in rules["rules"]:
            n = ids.get(ruleIdentity(r))
            if n:
                r["lastUsed"] = nowText()
                r["uses"] = int(r.get("uses", 0)) + n
                changed = True
        if changed:
            saveRules(rules)


def emptyRules():
    return {"rules": [], "pending": []}


class RulesFileError(Exception):
    pass


def validateRules(data):
    if not isinstance(data, dict):
        raise RulesFileError("top level must be an object")
    data.setdefault("rules", [])
    data.setdefault("pending", [])
    for name in ("rules", "pending"):
        if not isinstance(data[name], list):
            raise RulesFileError(f'"{name}" must be a list')
    hosts = data.get("hosts", {})
    if not isinstance(hosts, dict) or not all(
            isinstance(v, list) and all(isinstance(x, str) for x in v) for v in hosts.values()):
        raise RulesFileError('"hosts" must map a name to a list of aliases')
    grants = data.get("grants", {})
    if not isinstance(grants, dict) or not all(
            isinstance(v, dict) and isinstance(v.get("git", []), list)
            and isinstance(v.get("cmds", []), list) for v in grants.values()):
        raise RulesFileError('"grants" must map a session id to {"git": [...], "cmds": [...]}')
    HOST_ALIASES[:] = [{k.lower(), *(x.lower() for x in v)} for k, v in hosts.items()]
    validateRuleList(data["rules"], "rules")
    for i, p in enumerate(data["pending"]):
        if not isinstance(p, dict) or not isinstance(p.get("rules"), list) \
                or not all(isinstance(r, dict) for r in p["rules"]):
            raise RulesFileError(f'pending[{i}] needs a "rules" list of objects')
    return data


def validateRuleList(rules, label):
    for i, r in enumerate(rules):
        if not isinstance(r, dict) or not isinstance(r.get("kind"), str) \
                or not isinstance(r.get("match"), str):
            raise RulesFileError(f'{label}[{i}] needs string "kind" and "match"')
        if r.get("decision") not in ("allow", "ask", "deny"):
            raise RulesFileError(f'{label}[{i}] "decision" must be "allow", "ask" or "deny"')
        if r.get("match", "").startswith("re:"):
            try:
                re.compile(r["match"][3:])
            except re.error as e:
                raise RulesFileError(f"{label}[{i}] bad regex: {e}")


def loadRules():
    """Returns the rules data. Raises RulesFileError if the file can't be used;
    a missing file is just empty."""
    try:
        with open(RULES_PATH) as f:
            data = json.load(f)
    except FileNotFoundError:
        data = emptyRules()
    except ValueError as e:
        raise RulesFileError(f"invalid JSON: {e}")
    except OSError as e:
        raise RulesFileError(f"can't read: {e}")
    data = validateRules(data)
    for path in folderFiles():
        name = os.path.basename(path)
        try:
            with open(path) as f:
                part = json.load(f)
        except (OSError, ValueError) as e:
            raise RulesFileError(f"{name}: {e}")
        if not isinstance(part, dict) or not isinstance(part.get("rules"), list):
            raise RulesFileError(f'{name}: needs a "rules" list')
        validateRuleList(part["rules"], name)
        data["rules"] += part["rules"]
    return data


# While the rules file is broken, new pending entries and approvals go here; they are
# merged into the rules file the next time it loads cleanly.
RECOVERY_PATH = os.path.join(HOOK_DIR, "sudoRmGuard-rules.recovery.json")
# folders with SPLIT_MIN+ rules get their own file here (by rule "path")
RULES_DIR = os.path.join(HOOK_DIR, "sudoRmGuard-rules.d")
# stale rules move here; still consulted, and a rule that decides a call moves back
ARCHIVE_PATH = os.path.join(HOOK_DIR, "sudoRmGuard-rules.archive.json")
MAINT_STAMP = os.path.join(HOOK_DIR, ".sudoRmGuard-maintenance")
DESKTOP_SESSIONS_DIR = os.path.join(HOME, ".config", "Claude", "claude-code-sessions")


def loadRecovery():
    try:
        with open(RECOVERY_PATH) as f:
            rec = json.load(f)
        rec.setdefault("pending", [])
        rec.setdefault("approved", [])
        return rec
    except (OSError, ValueError, AttributeError):
        return {"pending": [], "approved": []}


def saveRecovery(rec):
    tmp = RECOVERY_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f, indent=2)
    os.replace(tmp, RECOVERY_PATH)


def mergeRecovery(rules):
    """Fold recovery data into a cleanly-loaded rules dict. Returns True if anything
    changed (caller saves, then deletes the recovery file)."""
    if not os.path.exists(RECOVERY_PATH):
        return False
    rec = loadRecovery()
    have = {p.get("toolUseId") for p in rules["pending"]}
    rules["pending"] += [p for p in rec["pending"] if p.get("toolUseId") not in have]
    for tid in rec["approved"]:
        learnApproval(rules, tid)
    return True


class Lock:
    def __enter__(self):
        self.f = open(RULES_PATH + ".lock", "w")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def isLiteralScriptRule(r):
    m = r.get("match", "")
    return r.get("kind") == "script" and r.get("sha", "*") != "*" \
        and "*" not in m and not m.startswith("re:")


def cleanupRules(rules):
    """Drop script rules for files that no longer exist, and script rules superseded
    by a newer rule for the same path/scope/decision (their sha can't match any more).
    Rules with sha "*" or a wildcard/regex match are left alone."""
    newest = {}
    for r in rules:
        if isLiteralScriptRule(r):
            k = (r["match"], bool(r.get("sudo")), r.get("session"), r.get("path"), r.get("env"), r.get("decision"))
            if k not in newest or r.get("at", "") >= newest[k].get("at", ""):
                newest[k] = r
    out = []
    for r in rules:
        if isLiteralScriptRule(r):
            k = (r["match"], bool(r.get("sudo")), r.get("session"), r.get("path"), r.get("env"), r.get("decision"))
            if newest[k] is not r or not os.path.exists(r["match"]):
                continue
        out.append(r)
    return out


def saveRules(data):
    """Write rules: big folders go to sudoRmGuard-rules.d/<folder>.json, the rest to the
    main file. Hourly maintenance archives stale rules and marks superseded ones.
    Indented, fixed key order so the files are easy to hand-edit; sorted by date."""
    rules = cleanupRules(data["rules"])
    if maintenanceDue():
        rules = maintainRules(rules)
    data["rules"] = rules
    byPath = {}
    for r in rules:
        byPath.setdefault(r.get("path"), []).append(r)
    folderRules, mainRules = {}, []
    for path, rs in byPath.items():
        if isinstance(path, str) and path and (len(rs) >= SPLIT_MIN or os.path.exists(folderFile(path))):
            folderRules[path] = rs
        else:
            mainRules += rs
    writeJson(RULES_PATH, {
        "hosts": data.get("hosts", {}),
        "grants": data.get("grants", {}),
        "rules": orderedRules(mainRules),
        "pending": [orderedRule(p) for p in sorted(data["pending"], key=lambda p: p.get("at", ""))],
    })
    keep = set()
    for path, rs in folderRules.items():
        f = folderFile(path)
        keep.add(f)
        writeJson(f, {"path": path, "rules": orderedRules(rs)})
    for f in folderFiles():
        if f not in keep:
            os.remove(f)  # folder has no rules left


def orderedRule(r):
    out = {k: r[k] for k in RULE_KEY_ORDER if k in r}
    out.update({k: v for k, v in r.items() if k not in out})
    if "rules" in out:
        out["rules"] = [orderedRule(x) for x in out["rules"]]
    return out


def orderedRules(rules):
    return [orderedRule(r) for r in sorted(rules, key=lambda r: r.get("at", ""))]


def writeJson(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


def folderFile(path):
    slug = re.sub(r"[^\w.-]+", "_", path.strip("/")) or "root"
    return os.path.join(RULES_DIR, slug + ".json")


def folderFiles():
    try:
        return sorted(os.path.join(RULES_DIR, f) for f in os.listdir(RULES_DIR) if f.endswith(".json"))
    except OSError:
        return []


# ---------------------------------------------------------------- maintenance

def maintenanceDue():
    try:
        return time.time() - os.path.getmtime(MAINT_STAMP) > MAINT_INTERVAL
    except OSError:
        return True


def maintainRules(rules):
    """Archive stale rules and refresh supersededBy marks. Returns the remaining rules."""
    try:
        open(MAINT_STAMP, "a").close()
        os.utime(MAINT_STAMP)
    except OSError:
        pass
    try:
        archive = loadArchive(strict=True)
    except RulesFileError:
        archive = None  # broken archive: don't add to it, keep everything live
    if archive is not None:
        archivedSessions = desktopArchivedSessions()
        stay, moved = [], []
        for r in rules:
            (moved if shouldArchive(r, archivedSessions) else stay).append(r)
        if moved:
            for r in moved:
                r["archivedAt"] = nowText()
            writeJson(ARCHIVE_PATH, {"rules": orderedRules(archive + moved)})
            rules = stay
    markSuperseded(rules)
    return rules


def desktopArchivedSessions():
    """CLI session ids the Claude desktop app shows as archived."""
    out = set()
    try:
        files = [os.path.join(dp, f) for dp, _, fs in os.walk(DESKTOP_SESSIONS_DIR)
                 for f in fs if f.startswith("local_") and f.endswith(".json")]
    except OSError:
        return out
    for f in files:
        try:
            with open(f) as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(d, dict) and d.get("isArchived") and d.get("cliSessionId"):
            out.add(d["cliSessionId"])
    return out


def isCustomized(r):
    """Hand-widened rules are worth keeping even when idle."""
    m = r.get("match", "")
    return "*" in m or m.startswith("re:") or "{" in m or r.get("session") == "*" \
        or r.get("sha") == "*" or r.get("env") == "*" or r.get("path") == "/"


def idleDays(r):
    stamp = r.get("lastUsed") or r.get("at") or ""
    try:
        t = time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return 0
    return (time.time() - t) / 86400


def shouldArchive(r, archivedSessions):
    if r.get("decision") != "allow" or isCustomized(r):
        return False
    idle = idleDays(r)
    if r.get("session") in archivedSessions and idle >= ARCHIVED_SESSION_IDLE_DAYS:
        return True
    return idle >= ARCHIVE_IDLE_DAYS and int(r.get("uses", 0)) < ARCHIVE_MAX_USES


def pathCovers(outer, inner):
    if outer == inner or outer == "/":
        return True
    return isinstance(outer, str) and isinstance(inner, str) and \
        inner.startswith(outer.rstrip("/") + "/")


def covers(o, r):
    """o matches everything r matches, with equal or wider scope."""
    if o.get("kind") != r.get("kind") or o.get("decision") != r.get("decision"):
        return False
    if "{" in o.get("match", "") or "{" in r.get("match", ""):
        return False
    if o.get("session") not in ("*", r.get("session")) or not pathCovers(o.get("path"), r.get("path")):
        return False
    if o.get("env") not in ("*", r.get("env")) or (r.get("sudo") and not o.get("sudo")):
        return False
    if o.get("sha", "*") not in ("*", r.get("sha")):
        return False
    if r.get("match", "").startswith("re:"):
        return o.get("match") == r.get("match")
    if r.get("kind") == "container":
        return containerMatches(o.get("match", ""), r.get("match", ""))
    return textMatches(o.get("match", ""), r.get("match", ""))


def markSuperseded(rules):
    """supersededBy = match of a rule that already covers this one (for manual cleanup).
    Of two identical rules, the newer one is marked."""
    order = sorted(range(len(rules)), key=lambda i: (rules[i].get("at", ""), i))
    rank = {id(rules[i]): n for n, i in enumerate(order)}
    for r in rules:
        r.pop("supersededBy", None)
        for o in rules:
            if o is r or not covers(o, r):
                continue
            if covers(r, o) and rank[id(o)] > rank[id(r)]:
                continue  # equivalent: keep the older one unmarked
            r["supersededBy"] = o.get("match")
            break


def loadArchive(strict=False):
    try:
        with open(ARCHIVE_PATH) as f:
            data = json.load(f)
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise ValueError('needs a "rules" list')
        validateRuleList(data["rules"], os.path.basename(ARCHIVE_PATH))
        return data["rules"]
    except FileNotFoundError:
        return []
    except (OSError, ValueError, RulesFileError) as e:
        if strict:
            raise RulesFileError(f"{os.path.basename(ARCHIVE_PATH)}: {e}")
        return []


def reviveRules(revived):
    """Archived rules that decided a call move back into the live rules."""
    if not revived:
        return
    ids = {ruleIdentity(r) for r in revived}
    with Lock():
        try:
            archive = loadArchive(strict=True)
            rules = loadRules()
        except RulesFileError:
            return
        back = [r for r in archive if ruleIdentity(r) in ids]
        if not back:
            return
        for r in back:
            r.pop("archivedAt", None)
        writeJson(ARCHIVE_PATH, {"rules": orderedRules([r for r in archive if ruleIdentity(r) not in ids])})
        rules["rules"] += back
        saveRules(rules)


def prunePending(pending):
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - PENDING_TTL))
    pending = [p for p in pending if p.get("at", "") >= cutoff]
    return sorted(pending, key=lambda p: p.get("at", ""))[-PENDING_MAX:]


def rulesFileWarning(err):
    return f"\u26a0 {os.path.basename(RULES_PATH)} is unusable ({err}); asking about every " \
        "command until it's fixed. Approvals are still remembered. "


def openRules():
    """Load rules, folding in recovery data if the file is healthy again.
    Returns (rules or None, error or None). Caller must hold the lock if it will save."""
    try:
        rules = loadRules()
    except RulesFileError as e:
        return None, str(e)
    if mergeRecovery(rules):
        saveRules(rules)
        try:
            os.remove(RECOVERY_PATH)
        except OSError:
            pass
    return rules, None


def recordPending(rules, entry):
    sig = [(p["kind"], p["match"], p.get("sha")) for p in entry["rules"]]
    same = [p for p in rules["pending"]
            if [(r.get("kind"), r.get("match"), r.get("sha")) for r in p["rules"]] == sig]
    if same:
        # repeat of an ask still pending: keep its rules (the user may have edited
        # them), just point it at this call
        entry["rules"] = same[-1]["rules"]
        rules["pending"] = [p for p in rules["pending"] if p not in same]
    rules["pending"].append(entry)
    rules["pending"] = prunePending(rules["pending"])


def learnApproval(rules, tid):
    """Move pending entry tid's rules into rules (with any decision the user edited in)."""
    entry = next((p for p in rules["pending"] if p.get("toolUseId") == tid), None)
    if not entry:
        return False
    rules["pending"].remove(entry)
    ident = lambda r: (r.get("kind"), r.get("match"), r.get("sha"), r.get("sudo"),
                       r.get("session"), r.get("path"), r.get("env"))
    have = {ident(r) for r in rules["rules"]}
    for r in entry["rules"]:
        # the approved command may have edited the script before running it; what you
        # approved is the post-edit file, so remember that content
        if r.get("kind") == "script" and r.get("sha", "*") != "*":
            try:
                with open(r["match"], "rb") as f:
                    r["sha"] = sha(f.read(16 * 1024 * 1024))
            except OSError:
                pass
        if ident(r) not in have:
            r["at"] = nowText()
            rules["rules"].append(r)
    return True
