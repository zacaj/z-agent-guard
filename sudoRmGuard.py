#!/usr/bin/env python3
"""PreToolUse hook for Bash: decides sudo/rm/rmdir commands.

- rm/rmdir whose every path is strictly inside a scratch root -> ok
- sudo running a read-only command from SAFE_SUDO -> ok
- any other sudo/rm, or anything we can't parse -> "ask"
- commands with no sudo/rm at all -> no output (normal rules + classifier)

If every sudo/rm part is ok AND every other part is trivially safe, returns
"allow". If the sudo/rm parts are ok but other parts aren't trivial, returns
nothing so the other parts still go through the normal rules/classifier
(a hook "allow" would approve the whole compound command).

Unsure -> "ask". A parse bug should only ever cost an extra prompt.

Test: python3 sudoRmGuard.py --test "<command>" [cwd]
"""
import json
import os
import re
import shlex
import sys

HOME = os.path.expanduser("~")
SCRATCH_ROOTS = ["/tmp", os.path.join(HOME, "tmp")]

# sudo <cmd>: read-only commands, with args that would make them write rejected
SAFE_SUDO = {"ls", "cat", "grep", "egrep", "zgrep", "head", "tail", "dmesg", "journalctl",
             "strings", "objdump", "readelf", "pgrep", "stat", "file", "wc", "du", "lsof",
             "ss", "lsblk", "blkid", "xxd", "hexdump", "od", "md5sum", "sha256sum", "id", "true", "dmidecode"}
SAFE_SUDO_BAD_ARGS = {
    "dmesg": re.compile(r"^-(\w*[cCDEn]\w*)$|^--(clear|read-clear|console-)"),
    "journalctl": re.compile(r"^--(vacuum|rotate|flush|relinquish|sync|setup-keys|update-catalog)"),
    "lsof": re.compile(r"^\+"),  # harmless, but keep the list explicit
}
SUDO_OK_FLAGS = {"-n", "--non-interactive"}

# commands considered harmless enough to approve alongside a safe sudo/rm
TRIVIAL = {"cd", "echo", "printf", "true", "false", ":", "sleep", "ls", "cat", "pwd", "test",
           "[", "set", "wc", "head", "tail", "grep", "sort", "uniq", "date"}
# wrappers that run their remaining args as a command
EXEC_WRAPPERS = {"nohup", "nice", "ionice", "time", "command", "exec", "stdbuf", "unbuffer",
                 "env", "timeout", "xargs", "watch", "flock", "setsid"}
SHELLS = {"bash", "sh", "zsh", "dash", "fish"}
GUARDED = {"sudo", "rm", "rmdir"}
GLOB_CHARS = set("*?[")
OPS = {";", "&&", "||", "|", "|&", "&", "(", ")", "\n"}


class Ask(Exception):
    pass


def realRoots():
    return [os.path.realpath(r) for r in SCRATCH_ROOTS]


def stripHeredocs(cmd):
    """Remove heredoc bodies. Returns (cmd, [(lineBeforeBody, body)])."""
    bodies = []
    out = []
    lines = cmd.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        tags = re.findall(r"<<-?\s*(['\"]?)(\w+)\1", line)
        i += 1
        for _, tag in tags:
            body = []
            while i < len(lines) and lines[i].strip() != tag:
                body.append(lines[i])
                i += 1
            if i >= len(lines):
                raise Ask("unterminated heredoc")
            i += 1
            bodies.append((line, "\n".join(body)))
    return "\n".join(out), bodies


def newlinesToSemicolons(cmd):
    """Unquoted newlines separate commands; shlex would treat them as spaces."""
    out, quote, i = [], None, 0
    while i < len(cmd):
        c = cmd[i]
        if quote:
            if c == "\\" and quote == '"':
                out.append(cmd[i:i + 2])
                i += 2
                continue
            if c == quote:
                quote = None
        elif c == "\\":
            out.append(cmd[i:i + 2])
            i += 2
            continue
        elif c in "'\"":
            quote = c
        elif c == "\n":
            c = ";"
        out.append(c)
        i += 1
    return "".join(out)


def tokenize(cmd):
    cmd = newlinesToSemicolons(cmd.replace("\\\n", " "))
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>")
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError as e:
        raise Ask(f"unparseable: {e}")


def splitCommands(toks):
    cmds, cur = [], []
    for t in toks:
        if t in OPS or (set(t) <= set(";&|()") and t):
            if cur:
                cmds.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        cmds.append(cur)
    return cmds


def stripRedirects(words):
    out, skip = [], False
    for w in words:
        if skip:
            skip = False
            continue
        if re.fullmatch(r"\d*(>>?|<<?<?|>&|<&|&>>?)", w):
            skip = True
            continue
        if re.fullmatch(r"\d*>&\d+|\d*<&\d+", w):
            continue
        out.append(w)
    return out


ASSIGN_RE = re.compile(r"^([A-Za-z_]\w*)=(.*)$", re.S)


class Ctx:
    def __init__(self, cwd):
        self.cwd = cwd
        self.vars = {"HOME": HOME}
        self.sawGuarded = False
        self.allTrivial = True
        self.reasons = []


def expandVars(s, ctx):
    def rep(m):
        name = m.group(1) or m.group(2)
        if name not in ctx.vars:
            raise Ask(f"unknown variable ${name}")
        return ctx.vars[name]
    if "`" in s or "$(" in s:
        raise Ask("command substitution in path")
    s = re.sub(r"\$\{(\w+)\}|\$(\w+)", rep, s)
    if "$" in s:
        raise Ask("unexpandable $ in path")
    if s == "~" or s.startswith("~/"):
        s = HOME + s[1:]
    return s


def isUnderRoot(path, ctx):
    """path: expanded string, may contain a glob."""
    if not os.path.isabs(path):
        if ctx.cwd is None:
            raise Ask("relative path with unknown cwd")
        path = os.path.join(ctx.cwd, path)
    globIdx = next((i for i, c in enumerate(path) if c in GLOB_CHARS), None)
    if globIdx is not None:
        head = path[:globIdx]
        rest = path[globIdx:]
        if ".." in rest.split("/"):
            return False
        # dir containing the glob must be inside a root
        base = head if head.endswith("/") else os.path.dirname(head)
        target = os.path.realpath(base)
        # strictly below a root: "rm /tmp/*" would hit other programs' files
        return any(target.startswith(r + "/") for r in realRoots())
    norm = os.path.normpath(path)
    # don't follow the final component (rm removes the link, not its target)
    parent = os.path.realpath(os.path.dirname(norm))
    full = os.path.join(parent, os.path.basename(norm))
    return any(full.startswith(r + "/") for r in realRoots())


def checkRm(args, ctx):
    endOfOpts = False
    paths = []
    for a in args:
        if not endOfOpts and a == "--":
            endOfOpts = True
        elif not endOfOpts and a.startswith("-") and a != "-":
            if not re.fullmatch(r"-[rRfvdI]+|--(recursive|force|verbose|dir)", a):
                raise Ask(f"rm flag {a}")
        else:
            paths.append(a)
    if not paths:
        raise Ask("rm with no paths")
    for p in paths:
        e = expandVars(p, ctx)
        if not isUnderRoot(e, ctx):
            raise Ask(f"rm outside scratch roots: {p}")


def checkSudo(args, ctx):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] not in SUDO_OK_FLAGS:
            raise Ask(f"sudo flag {args[i]}")
        i += 1
    rest = args[i:]
    if not rest:
        raise Ask("bare sudo")
    name = os.path.basename(rest[0])
    if name not in SAFE_SUDO:
        raise Ask(f"sudo {name}")
    bad = SAFE_SUDO_BAD_ARGS.get(name)
    if bad and any(bad.search(a) for a in rest[1:]):
        raise Ask(f"sudo {name} with write flag")
    if any("$(" in a or "`" in a for a in rest[1:]):
        raise Ask("command substitution under sudo")


def mentionsGuarded(s):
    return re.search(r"(^|[^\w.-])(sudo|rm|rmdir)(\s|$|;|\))", s) is not None


def analyzeCommand(words, ctx, depth):
    words = stripRedirects(words)
    while words and ASSIGN_RE.match(words[0]):
        k, v = ASSIGN_RE.match(words[0]).groups()
        try:
            ctx.vars[k] = expandVars(v, ctx)
        except Ask:
            ctx.vars.pop(k, None)  # unknown value; using it later will Ask
        words = words[1:]
    if not words:
        return
    name = os.path.basename(words[0])
    args = words[1:]

    if name in EXEC_WRAPPERS:
        # drop wrapper options/durations/env assignments, then analyze the rest
        j = 0
        while j < len(args) and (args[j].startswith("-") or ASSIGN_RE.match(args[j])
                                 or (name == "timeout" and re.fullmatch(r"[\d.]+[smhd]?", args[j]))):
            j += 1
        if any(mentionsGuarded(a) for a in args):
            if name in ("xargs", "watch", "flock", "setsid"):
                raise Ask(f"{name} running guarded command")
            analyzeCommand(args[j:], ctx, depth)
        elif args[j:]:
            analyzeCommand(args[j:], ctx, depth)
        return

    if name in SHELLS:
        if "-c" in args:
            script = args[args.index("-c") + 1] if args.index("-c") + 1 < len(args) else ""
            if mentionsGuarded(script):
                if depth > 3:
                    raise Ask("nesting too deep")
                analyzeScript(script, ctx, depth + 1)
                ctx.allTrivial = False
                return
        ctx.allTrivial = False
        return

    if name == "eval":
        if any(mentionsGuarded(a) for a in args):
            raise Ask("eval with guarded command")
        ctx.allTrivial = False
        return

    if name == "find":
        for k, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir") and k + 1 < len(args):
                if os.path.basename(args[k + 1]) in GUARDED:
                    raise Ask("find -exec rm/sudo")
        ctx.allTrivial = False
        return

    if name == "cd":
        target = args[0] if args else HOME
        try:
            t = expandVars(target, ctx)
            ctx.cwd = os.path.normpath(os.path.join(ctx.cwd, t)) if ctx.cwd else (t if os.path.isabs(t) else None)
        except Ask:
            ctx.cwd = None
        return

    if name in ("rm", "rmdir"):
        ctx.sawGuarded = True
        checkRm(args, ctx)
        return
    if name == "sudo":
        ctx.sawGuarded = True
        checkSudo(args, ctx)
        return

    if name not in TRIVIAL:
        ctx.allTrivial = False


def analyzeScript(cmd, ctx, depth=0):
    cmd, bodies = stripHeredocs(cmd)
    for line, body in bodies:
        if mentionsGuarded(body):
            # body fed to a shell (bash <<EOF, sudo bash <<EOF, ssh host <<EOF ...)
            if re.search(r"(^|[\s;&|(])(bash|sh|zsh|dash|sudo|ssh)\b", line):
                if re.search(r"\bssh\b", line):
                    pass  # remote; ssh itself is handled by rules
                else:
                    raise Ask("heredoc script containing sudo/rm")
    # command substitutions containing guarded words
    for sub in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", cmd):
        s = sub[0] or sub[1]
        if mentionsGuarded(s):
            analyzeScript(s, ctx, depth + 1)
            ctx.allTrivial = False
    toks = tokenize(cmd)
    for words in splitCommands(toks):
        analyzeCommand(words, ctx, depth)


def decide(cmd, cwd):
    """Returns (decision or None, reason)."""
    if not mentionsGuarded(cmd):
        return None, "no sudo/rm"
    ctx = Ctx(cwd)
    try:
        analyzeScript(cmd, ctx)
    except Ask as e:
        return "ask", f"sudoRmGuard: {e}"
    except Exception as e:  # any bug -> ask, never allow
        return "ask", f"sudoRmGuard error: {type(e).__name__}: {e}"
    if not ctx.sawGuarded:
        return None, "sudo/rm only mentioned in args"
    if ctx.allTrivial:
        return "allow", "sudoRmGuard: safe sudo read / scratch rm"
    return None, "sudoRmGuard: sudo/rm parts safe; rest left to rules"


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--test":
        cwd = sys.argv[3] if len(sys.argv) > 3 else os.getcwd()
        print(decide(sys.argv[2], cwd))
        return
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    cmd = (data.get("tool_input") or {}).get("command", "")
    decision, reason = decide(cmd, data.get("cwd"))
    if decision:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }}))


if __name__ == "__main__":
    main()
