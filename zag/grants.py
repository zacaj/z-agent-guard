"""z-agent-guard: grants (moved verbatim from the single-file hook)."""
import json
import os
import re
import time

from .defaults import CMD_GRANT_RE, GIT_AUTH_RE, GIT_KEYWORD, GIT_MARKER_RE, GRANT_TTL_DAYS, HOME
from .util import nowText
from .storage import Lock, openRules, rulesFileWarning, saveRules


def lastUserText(transcriptPath):
    """Text of the user's most recent typed message (not tool results, hook or system text)."""
    try:
        with open(transcriptPath, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 4_000_000))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except (OSError, TypeError):
        return ""
    for line in reversed(lines):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("type") != "user" or d.get("isMeta") or d.get("isSidechain") \
                or d.get("isCompactSummary"):
            continue
        c = (d.get("message") or {}).get("content")
        if isinstance(c, list):
            if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c):
                continue
            c = " ".join(b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text")
        if not isinstance(c, str):
            continue
        c = stripInjected(c)
        if c:
            return c
    return ""


def stripInjected(text):
    """Drop injected blocks and `code` spans (quoted text never authorizes anything)."""
    text = re.sub(r"<(pasted_content|system-reminder|command-[\w-]+|local-command-[\w-]+)\b.*?</\1>",
                  "", text or "", flags=re.S)
    return re.sub(r"```.*?```|`[^`\n]*`", " ", text, flags=re.S).strip()


def gitMarkers(text):
    """[(keyword, suffix, atSentenceStart)] for each capitalized keyword."""
    out = []
    for m in GIT_AUTH_RE.finditer(text):
        before = text[:m.start()].rstrip(" \t")
        out.append((m.group(1).lower(), m.group(2) or "", not before or before[-1] in ".!?\n"))
    return out


def gitAuthFrom(text):
    """This turn's authorizations: Keyword or Keyword* mid-sentence. A capital at a
    sentence start is just grammar; quoted/emphasized words don't count either."""
    auth = set()
    for m in GIT_AUTH_RE.finditer(text):
        before = text[:m.start()].rstrip(" \t")
        if m.group(2) != "-*" and before and before[-1] not in ".!?\n\"'`*>":
            auth.add(m.group(1).lower())
    return auth


def isMarkersOnly(text):
    rest = GIT_MARKER_RE.sub(" ", CMD_GRANT_RE.sub(" ", text))
    return bool(text.strip()) and not re.sub(r"[\s,;]", "", rest)


def applyGrants(rules, session, gitAdd, gitDel, cmdAdd, cmdDel):
    grants = rules.setdefault("grants", {})
    g = grants.setdefault(session, {})
    git = (set(g.get("git", [])) | gitAdd) - gitDel
    cmds = [c for c in g.get("cmds", []) if c not in cmdDel]
    cmds += [c for c in cmdAdd if c not in cmds]
    g.update({"git": sorted(git), "cmds": cmds, "at": nowText()})
    if not git and not cmds:
        del grants[session]
    return git, cmds


def pruneGrants(grants):
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S",
                           time.localtime(time.time() - GRANT_TTL_DAYS * 86400))
    return {k: v for k, v in grants.items() if v.get("at", "") >= cutoff}


def settingsAskPatterns(cwd):
    """Bash(...) patterns from settings "ask" lists (user + project, best effort)."""
    paths = [os.path.join(HOME, ".claude", f) for f in ("settings.json", "settings.local.json")]
    if cwd:
        paths += [os.path.join(cwd, ".claude", f) for f in ("settings.json", "settings.local.json")]
    out = []
    for path in paths:
        try:
            with open(path) as f:
                ask = json.load(f).get("permissions", {}).get("ask", [])
        except (OSError, ValueError, AttributeError):
            continue
        for r in ask:
            m = re.fullmatch(r"Bash\((.*)\)", r.strip()) if isinstance(r, str) else None
            if m:
                out.append(m.group(1))
    return out


def literalPrefix(pattern):
    """Text before the first wildcard (ask patterns: '*' or ':*'; grants: '*', re:)."""
    if pattern.startswith("re:"):
        return re.split(r"[\\.\[\](){}*+?|^$]", pattern[3:], 1)[0].strip()
    return re.split(r":?\*", pattern, 1)[0].strip()


def askConflicts(cwd, gitAdd, cmdAdd):
    """Best guess: settings ask entries that would still prompt despite these grants."""
    asks = settingsAskPatterns(cwd)
    hits = []
    for k in sorted(gitAdd):
        subs = [s for s, kw in GIT_KEYWORD.items() if kw == k]
        # only broad entries ("git push*"); narrower ones (force etc.) are meant to keep asking
        hits += [a for a in asks if any(literalPrefix(a) in (f"git {s}", "git") for s in subs)
                 and re.fullmatch(r"[\s*:]*", a[len(literalPrefix(a)):].strip())]
    for c in cmdAdd:
        cp = literalPrefix(c)
        hits += [a for a in asks
                 if (lambda ap: ap.startswith(cp) or cp.startswith(ap))(literalPrefix(a))]
    hits = list(dict.fromkeys(hits))
    if not hits:
        return ""
    return (" \u26a0 settings 'ask' may still prompt for some of these (an ask there overrides "
            "the hook): " + ", ".join(f"Bash({h})" for h in hits[:8])
            + (" \u2026" if len(hits) > 8 else ""))


def promptBlock(reason):
    print(json.dumps({"decision": "block", "reason": reason}))


def promptContext(text):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                             "additionalContext": text}}))


def handlePrompt(data):
    """UserPromptSubmit: record session grants. A prompt that is only markers is recorded
    and blocked (the agent never sees it); a keyword at a sentence start is ambiguous, so
    that prompt is blocked with a reminder."""
    text = stripInjected(data.get("prompt", ""))
    session = data.get("session_id", "")
    if not text or text[0] in "/!":
        return
    marks = gitMarkers(text)
    markersOnly = isMarkersOnly(text)
    if not markersOnly:
        starts = sorted({k.capitalize() + suf for k, suf, st in marks if st})
        if starts:
            return promptBlock(
                f"Not sent: '{', '.join(starts)}' at the start of a sentence is ambiguous (git "
                "authorization keywords only count mid-sentence). Lowercase it if it isn't an "
                "authorization, or move it mid-sentence, then resend.")
    gitAdd = {k for k, suf, _ in marks if suf == "*"}
    gitDel = {k for k, suf, _ in marks if suf == "-*"}
    cmdAdd, cmdDel = [], []
    if markersOnly:
        for m in CMD_GRANT_RE.finditer(text):
            pat = m.group(1).strip()
            if pat.startswith("re:"):
                try:
                    re.compile(pat[3:])
                except re.error as e:
                    return promptBlock(f"Not recorded: bad regex in [{pat}]: {e}")
            (cmdAdd if m.group(2) == "*" else cmdDel).append(pat)
    if not (gitAdd or gitDel or cmdAdd or cmdDel):
        return
    with Lock():
        rules, err = openRules()
        if err:
            msg = "⚠ grants not recorded: " + rulesFileWarning(err)
            return promptBlock(msg) if markersOnly else promptContext(msg)
        rules["grants"] = pruneGrants(rules.get("grants", {}))
        git, cmds = applyGrants(rules, session, gitAdd, gitDel, cmdAdd, cmdDel)
        saveRules(rules)
    summary = "session grants now: " + (", ".join(
        [k.capitalize() for k in sorted(git)] + [f"[{c}]" for c in cmds]) or "none") \
        + askConflicts(data.get("cwd"), gitAdd, cmdAdd)
    if markersOnly:
        return promptBlock("✓ " + summary + " (not sent to the agent)")
    used = sorted({k.capitalize() + suf for k, suf, _ in marks if suf})
    promptContext(f"Permission markers in the user's message ({', '.join(used)}) were handled "
                  "by the permission hook: Keyword* grants that git operation for the rest of "
                  "this session, Keyword-* revokes it. They are not part of the request; read "
                  f"the message as if they were plain words. {summary}.")
