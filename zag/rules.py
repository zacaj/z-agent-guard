"""z-agent-guard: rules (moved verbatim from the single-file hook)."""
import json
import os
import re
import shlex

from .defaults import HOME, USAGE_FIELDS, VALUE_SHORT_FLAGS
from .util import nowText, short
from .parse import joinWords


# ---- same-host detection for ssh envs

_sshResolveCache = {}
_knownKeysCache = {}
HOST_ALIASES = []  # [set(names)], from the rules file's "hosts" section


def parseSshEnv(spec):
    """'user@host:port' -> (user or None, host, port or None)."""
    user, _, hostPort = spec.rpartition("@")
    host, port = hostPort, None
    m = re.fullmatch(r"(.+):(\d+)", hostPort)
    if m and not hostPort.startswith("["):
        host, port = m.group(1), m.group(2)
    return user or None, host, port


def sshResolve(user, host, port):
    """Effective (user, hostname, port) via `ssh -G` (applies ~/.ssh/config, no connect)."""
    key = (user, host, port)
    if key not in _sshResolveCache:
        cmd = ["ssh", "-G"] + (["-l", user] if user else []) + (["-p", port] if port else []) + [host]
        res = (user, host, port or "22")
        try:
            import subprocess
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
            cfg = dict(l.split(" ", 1) for l in out.splitlines() if " " in l)
            res = (cfg.get("user", user), cfg.get("hostname", host).lower(), cfg.get("port", port or "22"))
        except Exception:
            pass
        _sshResolveCache[key] = res
    return _sshResolveCache[key]


def knownHostKeys(hostname, port):
    """Host keys recorded for hostname[:port] in known_hosts (public keys only)."""
    key = (hostname, port)
    if key not in _knownKeysCache:
        entry = hostname if port == "22" else f"[{hostname}]:{port}"
        keys = set()
        try:
            import subprocess
            out = subprocess.run(["ssh-keygen", "-F", entry], capture_output=True, text=True,
                                 timeout=3).stdout
            for line in out.splitlines():
                f = line.split()
                if len(f) >= 3 and not line.startswith("#"):
                    keys.add((f[-2], f[-1]))
        except Exception:
            pass
        _knownKeysCache[key] = keys
    return _knownKeysCache[key]


def aliasGroup(name):
    name = name.lower()
    for g in HOST_ALIASES:
        if name in g:
            return g
    return {name}


def sameSshTarget(a, b):
    """Do two 'user@host:port' specs reach the same account on the same machine?"""
    ua, ha, pa = parseSshEnv(a)
    ub, hb, pb = parseSshEnv(b)
    ra, rb = sshResolve(ua, ha, pa), sshResolve(ub, hb, pb)
    if ra[0] != rb[0]:
        return False  # different remote user
    names = lambda h, r: aliasGroup(h) | aliasGroup(r[1])
    if names(ha, ra) & names(hb, rb):
        return True
    if (ra[1], ra[2]) == (rb[1], rb[2]):
        return True
    ka, kb = knownHostKeys(ra[1], ra[2]), knownHostKeys(rb[1], rb[2])
    return bool(ka & kb)


def envMatches(ruleEnv, partEnv):
    here = partEnv or currentEnv()
    if ruleEnv is None or ruleEnv == "":
        return not here.startswith("ssh:")  # unscoped rules never apply to remote hosts
    if ruleEnv == "*" or textMatches(ruleEnv, here):
        return True
    if ruleEnv.startswith("ssh:") and here.startswith("ssh:") \
            and "*" not in ruleEnv and not ruleEnv.startswith("re:"):
        return sameSshTarget(ruleEnv[4:], here[4:])
    return False


def expandPlaceholders(pattern, project):
    """{project} = the call's project dir (git root, else cwd), {home} = home dir."""
    if "{" not in pattern:
        return pattern
    vals = {"{project}": (project or "/").rstrip("/") or "/", "{home}": HOME}
    for k, v in vals.items():
        pattern = pattern.replace(k, re.escape(v) if pattern.startswith("re:") else v)
    return pattern


def textMatches(pattern, text):
    if pattern.startswith("re:"):
        try:
            return re.fullmatch(pattern[3:], text, re.S) is not None
        except re.error:
            return False
    return re.fullmatch(globToRegex(pattern), text, re.S) is not None


def globToRegex(pattern):
    """'*' = any run of non-whitespace (stays within one word/flag value);
    '**' = any text including spaces; a trailing '*$' = same as a trailing '**'."""
    if pattern.endswith("*$"):
        pattern = pattern[:-2] + "**"
    one = lambda t: ".*".join(r"\S*".join(re.escape(p) for p in c.split("*")) for c in t.split("**"))
    # " ** " may also match nothing: "a ** b" matches "a b"
    return r"(?:\s.*\s|\s)".join(one(t) for t in pattern.split(" ** "))


def containerMatches(pattern, key):
    """Piece-wise: same head, every flag/mount in the command matches one of the rule's
    flag patterns, image matches, command matches."""
    if pattern.startswith("re:"):
        return textMatches(pattern, key)
    rHead, rFlags, rImage, rCmd = containerUnits(pattern)
    head, flags, image, cmd = containerUnits(key)
    if [h.lower() for h in rHead] != [h.lower() for h in head]:
        return False
    flagRx = [re.compile(globToRegex(f)) for f in rFlags]
    if not all(any(rx.fullmatch(f) for rx in flagRx) for f in flags):
        return False
    if rImage.endswith("*$"):  # "image*$": that image, any command
        return textMatches(rImage, image + (" " + joinWords(cmd) if cmd else ""))
    if not textMatches(rImage, image):
        return False
    return textMatches(joinWords(rCmd) if rCmd else "", joinWords(cmd))


_envCache = []


def currentEnv():
    """'host', or 'container:<name>' when the hook runs inside podman/docker."""
    if not _envCache:
        env = "host"
        try:
            with open("/run/.containerenv") as f:  # podman: has name="..."
                m = re.search(r'^name="([^"]*)"', f.read(), re.M)
            env = "container:" + (m.group(1) if m and m.group(1) else os.uname().nodename)
        except OSError:
            if os.path.exists("/.dockerenv"):
                env = "container:" + os.uname().nodename
        _envCache.append(env)
    return _envCache[0]


def scopeMatches(rule, session, project, partEnv=None):
    s = rule.get("session", "*")
    if s not in ("*", session):
        return False
    if not envMatches(rule.get("env"), partEnv):
        return False
    p = (rule.get("path") or "/").rstrip("/") or "/"
    return p == "/" or project == p or project.startswith(p + "/")


def ruleMatches(rule, part, session, project):
    if rule.get("kind") != part.kind or not scopeMatches(rule, session, project, part.env):
        return False
    # sudo parts need an explicit "sudo": true; a sudo rule also covers the non-sudo form
    if part.kind in ("script", "inline", "pkill") and part.sudo and not rule.get("sudo"):
        return False
    if part.kind == "script" and rule.get("sha", "*") not in ("*", part.sha):
        return False
    match = expandPlaceholders(rule.get("match", ""), project)
    if part.kind == "container":
        return containerMatches(match, part.match)
    return textMatches(match, part.match)


def specificity(rule):
    """Sort key: higher = more specific. Compared in order session, path, env, match."""
    sessionSpec = 1 if rule.get("session") not in (None, "", "*") else 0
    path = (rule.get("path") or "/").rstrip("/")
    pathSpec = len([p for p in path.split("/") if p])
    env = rule.get("env") or "*"
    envSpec = 0 if env == "*" else (1 if ("*" in env or env.startswith("re:")) else 2)
    m = rule.get("match", "")
    literal = len(m.replace("*", ""))
    if m.startswith("re:") or m.endswith("*$"):
        matchSpec = (0, literal)
    elif "*" in m:
        matchSpec = (1, literal)
    else:
        matchSpec = (2, literal)
    return (sessionSpec, pathSpec, envSpec, matchSpec)


def lookup(rules, part, session, project):
    """'deny' if any matching deny rule (regardless of specificity); otherwise the
    decision of the most specific matching rule ('allow'/'ask'), else None.
    Equally specific allow + ask -> 'ask'."""
    for r in rules:
        if r.get("decision") == "deny" and ruleMatches(r, part, session, project):
            USED_RULES.append(r)
            return "deny"
    best, bestRule, bestKey = None, None, None
    for r in rules:
        if r.get("decision") not in ("allow", "ask") or not ruleMatches(r, part, session, project):
            continue
        k = specificity(r)
        if bestKey is None or k > bestKey or (k == bestKey and r.get("decision") == "ask"):
            best, bestRule, bestKey = r.get("decision"), r, k
    if bestRule is not None:
        USED_RULES.append(bestRule)
    return best


# rules that decided something during the current decide() call (for lastUsed/uses)
USED_RULES = []
REVIVED = []  # archived rules that decided the current call


def ruleIdentity(r):
    return json.dumps({k: v for k, v in r.items() if k not in USAGE_FIELDS}, sort_keys=True)


def containerUnits(key):
    """Split a container key into (head, flagUnits, image, command)."""
    toks = shlex.split(key) if key.count("'") % 2 == 0 else key.split()
    i = 0
    while i < len(toks) and toks[i] not in ("run", "create"):
        i += 1
    head, i = toks[:i + 1], i + 1
    flags = []
    while i < len(toks) and toks[i].startswith("-"):
        if toks[i] in VALUE_SHORT_FLAGS and i + 1 < len(toks):
            flags.append(f"{toks[i]} {toks[i + 1]}")
            i += 2
        else:
            flags.append(toks[i])
            i += 1
    image = toks[i] if i < len(toks) else ""
    return head, flags, image, toks[i + 1:]


def explainPart(part, rules, session, project):
    """For an unmatched part, describe how it differs from the closest literal rule."""
    cands = [r for r in rules if r.get("kind") == part.kind and r.get("decision") == "allow"
             and scopeMatches(r, session, project, part.env)
             and (not part.sudo or r.get("sudo") or part.kind in ("cmd", "container"))
             and "*" not in r.get("match", "") and not r.get("match", "").startswith("re:")]
    if part.kind == "script":
        same = [r for r in cands if r["match"] == part.match and bool(r.get("sudo")) == bool(part.sudo)]
        if same:
            return f"content changed since approved {max(r.get('at', '') for r in same)}"
        return "never approved"
    if part.kind == "container":
        head, flags, image, cmd = containerUnits(part.match)
        best, bestScore = None, -1
        for r in cands:
            h, f, im, c = containerUnits(r["match"])
            if h != head:
                continue
            score = len(set(f) & set(flags)) + (3 if im == image else 0) + (1 if c == cmd else 0)
            if score > bestScore:
                best, bestScore = (h, f, im, c, r), score
        if not best:
            return f"no approved {' '.join(head)} rules yet"
        _, f, im, c, r = best
        diffs = []
        if im != image:
            diffs.append(f"image {short(im, 30)} → {short(image, 30)}")
        added = [x for x in flags if x not in f]
        removed = [x for x in f if x not in flags]
        if added:
            diffs.append("new " + ", ".join(short(x, 50) for x in added))
        if removed:
            diffs.append("dropped " + ", ".join(short(x, 50) for x in removed))
        if c != cmd:
            diffs.append(f"command '{short(joinWords(cmd))}' (was '{short(joinWords(c))}')")
        return f"vs rule from {r.get('at', '?')}: " + "; ".join(diffs or ["differs"])
    # cmd / pkill / inline: closest rule sharing the leading words
    words = part.match.split()
    best, bestN = None, 0
    for r in cands:
        w = r["match"].split()
        n = 0
        while n < min(len(w), len(words)) and w[n] == words[n]:
            n += 1
        if n > bestN:
            best, bestN = r, n
    if not best or bestN < min(2, len(words)):
        return ""
    return f"closest approved: '{short(best['match'], 80)}'"


def proposeRule(part, session, project):
    rule = {"decision": "allow", "kind": part.kind, "match": part.match}
    if part.kind == "script":
        rule.update(sha=part.sha, sudo=part.sudo)
    elif part.kind == "inline":
        rule.update(sudo=True, preview=part.preview)
    elif part.kind == "pkill":
        rule["sudo"] = True
    rule.update(session=session, path=project, env=part.env or currentEnv(), at=nowText(),
                # informational only: survives widening session/path to "*"
                **{"from": f"{currentEnv()} {project} session {session[:8]}"})
    return rule
