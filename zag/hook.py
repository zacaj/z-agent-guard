#!/usr/bin/env python3
"""Bash permission guard (PreToolUse + PostToolUse + PostToolUseFailure).

Each Bash call is split into subcommands ("parts"). Each part is one of:
- ok:      trivial (echo, cd, ...), read-only sudo, rm strictly inside /tmp or ~/tmp,
           read-only docker/podman subcommands
- defer:   anything else unguarded -> left to settings rules + auto-mode classifier
- guarded: needs a rule in sudoRmGuard-rules.json:
    script     running a script file (python3 x.py, bash x.sh, ./x.sh, sudo python3 x.py)
               keyed by path + content sha
    inline     sudo with an inline/heredoc script, keyed by script-text sha
    pkill      sudo pkill/killall of a named process
    container  [sudo] docker/podman run|create, keyed by privileges/mounts/image/command
    cmd        any other sudo / rm / destructive docker part, keyed by normalized text

Decision: any guarded part with no allow rule (or with an "ask" rule) -> "ask", and
its proposed rules go to "pending". All guarded parts allowed + everything else ok
-> "allow". Allowed but some part deferred -> no output (a hook allow would approve
the whole compound command).

PostToolUse/PostToolUseFailure: the call ran, so the user approved the prompt; the
pending entry's rules (with any decision the user edited in) move into "rules".

Rules file (hand-editable):
  decision  allow | ask   ("ask" keeps prompting even after you approve)
  match     normalized command text; "*" = any non-whitespace run (one word/value);
            trailing "*$" = rest of the command; "re:<regex>" = full-match regex.
            container rules match piece-wise: each flag/mount must match a rule flag
            (for script rules: the file path)
  session   session id or "*";  path  project dir, a parent dir, or "/"
  sha/sudo  script rules only; sha "*" = any content

Unsure -> "ask". A parse bug should only ever cost an extra prompt.

Test: python3 sudoRmGuard.py --test "<command>" [cwd]
"""
import json
import os
import re
import sys

from .defaults import INTEREST_RE
from .util import nowText, projectOf, short
from .parse import Ask
from .rules import REVIVED, USED_RULES, explainPart, lookup, proposeRule
from .storage import Lock, RulesFileError, emptyRules, learnApproval, loadArchive, loadRecovery, loadRules, openRules, prunePending, recordPending, recordUsage, reviveRules, rulesFileWarning, saveRecovery, saveRules
from .analyze import Ctx, Part, analyzeScript
from .grants import gitAuthFrom, handlePrompt, lastUserText


# ---------------------------------------------------------------- decision

def shapeNote(cmd, ctx):
    """Flag compound/multi-line commands so the asked-about part isn't the only thing
    you notice in a long command."""
    lines = cmd.count("\n") + 1
    bits = []
    if ctx.nCommands > 1:
        bits.append(f"{ctx.nCommands} commands")
    if lines > 1:
        bits.append(f"{lines} lines")
    if ctx.heredocBodies:
        n = len(ctx.heredocBodies)
        bits.append(f"{n} heredoc" + ("s" if n > 1 else ""))
    return f"[{', '.join(bits)}; asking about:] " if bits else ""


def decide(cmd, cwd, session="", data=None, gitAuth=()):
    """Returns (decision or None, reason, proposedRules). Rules that decided parts are
    left in USED_RULES."""
    USED_RULES.clear()
    REVIVED.clear()
    data = data if data is not None else loadRules()
    grant = data.get("grants", {}).get(session, {})
    if not INTEREST_RE.search(cmd) and not grant.get("cmds"):
        return None, "nothing guarded", []
    project = projectOf(cwd)
    ctx = Ctx(cwd)
    ctx.gitAuth = set(gitAuth) | set(grant.get("git", []))
    ctx.grantCmds = grant.get("cmds", [])
    ctx.rules = data["rules"]
    try:
        analyzeScript(cmd, ctx)
    except Ask as e:
        whole = Part("cmd", re.sub(r"\s+", " ", cmd).strip(), str(e))
        d = lookup(data["rules"], whole, session, project)
        if d == "deny":
            return "deny", f"sudo/rm guard: blocked by a deny rule ({e})", []
        if d == "allow":
            return None, f"sudo/rm guard: whole command allowed by rule ({e})", []
        return "ask", f"sudo/rm guard: {e}", [] if d == "ask" else [proposeRule(whole, session, project)]
    except Exception as e:  # any bug -> ask, never allow
        return "ask", f"sudo/rm guard error: {type(e).__name__}: {e}", []

    asks, proposals, seen = [], [], set()
    for part in ctx.parts:
        if (part.kind, part.match, part.sha, part.env) in seen:
            continue
        seen.add((part.kind, part.match, part.sha, part.env))
        d = lookup(data["rules"], part, session, project)
        if d is None and not data.get("noArchive"):
            n = len(USED_RULES)
            d = lookup(loadArchive(), part, session, project)
            REVIVED.extend(USED_RULES[n:])
        if d == "deny":
            return "deny", f"sudo/rm guard: blocked by a deny rule: '{short(part.match, 120)}'" + \
                (f" on {part.env}" if part.env else ""), []
        if d == "allow":
            continue
        if d == "ask":
            asks.append(part.desc + " [rule says ask]")
        else:
            why = explainPart(part, data["rules"], session, project)
            asks.append(part.desc + (f" ({why})" if why else ""))
            proposals.append(proposeRule(part, session, project))
    asks += ctx.gitAsks
    if asks:
        return "ask", "sudo/rm guard: " + shapeNote(cmd, ctx) + "; ".join(asks), proposals
    if ctx.allTrivial:
        return "allow", "sudo/rm guard: all guarded parts allowed", []
    return None, "sudo/rm guard: guarded parts allowed; rest left to rules", []


def handlePre(data):
    cmd = (data.get("tool_input") or {}).get("command", "")
    session = data.get("session_id", "")
    tid = data.get("tool_use_id")
    gitAuth = gitAuthFrom(lastUserText(data.get("transcript_path"))) \
        if re.search(r"\bgit\b", cmd) else set()
    with Lock():
        rules, err = openRules()
    if err and data.get("permission_mode") == "bypassPermissions":
        return  # can't check deny rules; skip-permissions means no prompts
    if err:
        # unusable rules file: ask about everything, but still record what we'd propose
        # so an approval now can be learned once the file is fixed
        _, reason, proposals = decide(cmd, data.get("cwd"), session, emptyRules(), gitAuth)
        decision = "ask"
        reason = rulesFileWarning(err) + (reason or "")
        if proposals and tid:
            with Lock():
                rec = loadRecovery()
                rec["pending"].append({"toolUseId": tid, "at": nowText(), "cmd": cmd[:500],
                                       "rules": proposals})
                rec["pending"] = prunePending(rec["pending"])
                saveRecovery(rec)
    else:
        decision, reason, proposals = decide(cmd, data.get("cwd"), session, rules, gitAuth)
        reviveRules(list(REVIVED))
        recordUsage(list(USED_RULES))
        if decision == "ask" and data.get("permission_mode") == "bypassPermissions":
            return  # skip-permissions session: a hook "ask" would still prompt; deny still applies
        if decision == "ask" and proposals and tid:
            with Lock():
                rules, err = openRules()
                entry = {"toolUseId": tid, "at": nowText(), "cmd": cmd[:500], "rules": proposals}
                if err:  # broke between the two reads
                    rec = loadRecovery()
                    rec["pending"].append(entry)
                    saveRecovery(rec)
                else:
                    recordPending(rules, entry)
                    saveRules(rules)
    if decision:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }}))


def handlePost(data):
    """The call ran, so if we asked about it the user approved: keep its rules."""
    tid = data.get("tool_use_id")
    if not tid:
        return
    with Lock():
        rules, err = openRules()
        if err:
            # can't touch the rules file; note the approval for when it's fixed, if we
            # might have asked about this call
            rec = loadRecovery()
            if tid not in rec["approved"]:
                rec["approved"].append(tid)
                rec["approved"] = rec["approved"][-200:]
                saveRecovery(rec)
            return
        if learnApproval(rules, tid):
            saveRules(rules)


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--test":
        cwd = sys.argv[3] if len(sys.argv) > 3 else os.getcwd()
        try:
            d, reason, props = decide(sys.argv[2], cwd, "test",
                                      gitAuth=os.environ.get("GIT_AUTH", "").split())
        except RulesFileError as e:
            d, reason, props = "ask", rulesFileWarning(e), []
        print(d, "|", reason)
        for p in props:
            print("   proposes:", json.dumps(p))
        return
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    if data.get("hook_event_name") == "UserPromptSubmit":
        handlePrompt(data)
        return
    if data.get("tool_name") != "Bash":
        return
    if data.get("hook_event_name", "").startswith("PostToolUse"):
        handlePost(data)
        return
    try:
        handlePre(data)
    except Exception as e:  # never let a crash fall through to "no decision"
        if data.get("permission_mode") == "bypassPermissions":
            return
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": f"sudo/rm guard crashed ({type(e).__name__}: {e}); asking to be safe",
        }}))


if __name__ == "__main__":
    main()
