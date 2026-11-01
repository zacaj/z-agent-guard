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
import fcntl
import hashlib
import json
import os
import re
import shlex
import sys
import time

HOME = os.path.expanduser("~")
HOOK_DIR = os.path.join(HOME, ".claude", "hooks")
RULES_PATH = os.path.join(HOOK_DIR, "sudoRmGuard-rules.json")
PENDING_TTL = 2 * 3600
PENDING_MAX = 50
SCRATCH_ROOTS = ["/tmp", os.path.join(HOME, "tmp")]

INTERP_RE = re.compile(r"^(python[\d.]*|node|perl|ruby|bash|sh|zsh|dash)$")
# cheap pre-filter: commands that can't contain anything guarded skip analysis
INTEREST_RE = re.compile(
    r"(^|[^\w.-])(sudo|rm|rmdir|docker|podman|ssh|python[\d.]*|node|perl|ruby|bash|sh|zsh|dash)(\s|$|;|\))"
    r"|(^|[\s;&|(])\.?\.?/[\w./-]+")

# sudo <cmd>: read-only commands, with args that would make them write rejected
SAFE_SUDO = {"ls", "cat", "grep", "egrep", "zgrep", "head", "tail", "dmesg", "journalctl",
             "strings", "objdump", "readelf", "pgrep", "stat", "file", "wc", "du", "lsof",
             "ss", "lsblk", "blkid", "xxd", "hexdump", "od", "md5sum", "sha256sum", "id", "true",
             "dmidecode"}
SAFE_SUDO_BAD_ARGS = {
    "dmesg": re.compile(r"^-(\w*[cCDEn]\w*)$|^--(clear|read-clear|console-)"),
    "journalctl": re.compile(r"^--(vacuum|rotate|flush|relinquish|sync|setup-keys|update-catalog)"),
}
SUDO_OK_FLAGS = {"-n", "--non-interactive"}

# harmless enough to approve alongside guarded parts
TRIVIAL = {"cd", "echo", "printf", "true", "false", ":", "sleep", "ls", "cat", "pwd", "test",
           "[", "set", "wc", "head", "tail", "grep", "sort", "uniq", "date"}
EXEC_WRAPPERS = {"nohup", "nice", "ionice", "time", "command", "exec", "stdbuf", "unbuffer",
                 "env", "timeout", "xargs", "watch", "flock", "setsid"}
SHELLS = {"bash", "sh", "zsh", "dash", "fish"}
GUARDED = {"sudo", "rm", "rmdir"}
GLOB_CHARS = set("*?[")
OPS = {";", "&&", "||", "|", "|&", "&", "(", ")", "\n"}

# docker/podman
CONTAINER_TOOLS = {"docker", "podman"}
CONTAINER_READONLY = {"ps", "logs", "inspect", "images", "info", "version", "stats", "top",
                      "port", "diff", "history", "events", "search"}
COMPOSE_READONLY = {"ps", "logs", "config", "images", "ls", "top", "version"}
CONTAINER_DESTRUCTIVE = {"rm", "rmi", "push", "login", "kill", "stop", "prune"}
# run/create flags kept in the rule (security relevant); value-taking ones listed
RUN_KEEP_FLAGS = {"--privileged"}
RUN_KEEP_VALUE = {"-v", "--volume", "--mount", "--cap-add", "--device", "--security-opt",
                  "-u", "--user", "--entrypoint", "--pid", "--ipc", "--userns", "--uts",
                  "--cgroupns", "--group-add"}
RUN_KEEP_NETWORK_HOST = {"--network", "--net"}
# run/create flags dropped from the rule, value-taking
RUN_DROP_VALUE = {"--name", "-e", "--env", "--env-file", "-p", "--publish", "-w", "--workdir",
                  "--label", "-l", "--hostname", "-h", "--restart", "--memory", "-m", "--cpus",
                  "--shm-size", "--platform", "--pull", "--log-driver", "--log-opt", "--add-host",
                  "--dns", "--network", "--net", "--stop-timeout", "--ulimit", "--tmpfs",
                  "--gpus", "--cidfile", "--init-path", "--expose", "--health-cmd",
                  "--mac-address", "--ip", "--ip6", "--domainname", "--stop-signal",
                  "--log-level", "--cpu-shares", "--memory-swap", "--annotation"}
RUN_BOOL_FLAGS = {"--rm", "--init", "--detach", "--interactive", "--tty", "--read-only",
                  "--replace", "--quiet", "-q", "--no-healthcheck", "--sig-proxy"}


class Ask(Exception):
    pass


# ---------------------------------------------------------------- parsing

def realRoots():
    return [os.path.realpath(r) for r in SCRATCH_ROOTS]


def stripHeredocs(cmd):
    """Remove heredoc bodies. Returns (cmd, [(lineBeforeBody, body)])."""
    # Scan with quote tracking so "<<" inside quoted text (python's `x << 20`, a regex)
    # isn't taken for a heredoc. Quotes can span lines (python -c "...multi-line...").
    bodies, out = [], []
    lines = cmd.split("\n")
    quote = None
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        tags = []
        k = 0
        while k < len(line):
            c = line[k]
            if quote:
                if c == "\\" and quote == '"':
                    k += 2
                    continue
                if c == quote:
                    quote = None
            elif c == "\\":
                k += 2
                continue
            elif c in "'\"":
                quote = c
            elif c == "#" and (k == 0 or line[k - 1] in " \t;&|("):
                break  # shell comment: rest of line ignored
            elif line.startswith("<<<", k):
                k += 3  # here-string, not a heredoc
                continue
            elif line.startswith("<<", k):
                m = re.match(r"<<-?\s*(['\"]?)([\w.-]+)\1", line[k:])
                if m:
                    tags.append(m.group(2))
                    k += m.end()
                    continue
            k += 1
        i += 1
        for tag in tags:
            body = []
            while i < len(lines) and lines[i].strip() != tag:
                body.append(lines[i])
                i += 1
            if i >= len(lines):
                raise Ask(f"unterminated heredoc (<<{tag})")
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


# fd plumbing that doesn't change what a command does: 2>&1, 2>/dev/null, &>/dev/null
NOISE_REDIRECT_RE = re.compile(r"(?<!\S)(\d*>&\d+|&?\d*>>?\s*/dev/null)(?=\s|$|[;&|)])")


def tokenize(cmd):
    cmd = newlinesToSemicolons(cmd.replace("\\\n", " "))
    cmd = NOISE_REDIRECT_RE.sub(" ", cmd)
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
        if t in OPS or (t and set(t) <= set(";&|()")):
            if cur:
                cmds.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        cmds.append(cur)
    return cmds


def stripRedirects(words):
    """Drop remaining redirections (> file, < file, 2> file). Returns (words, writesFile)."""
    out, skip, writes = [], False, False
    for k, w in enumerate(words):
        if skip:
            skip = False
            continue
        if re.fullmatch(r"(>>?|<<?<?|>&|<&|&>>?)", w):
            if out and re.fullmatch(r"\d+", out[-1]) and k > 0 and words[k - 1] == out[-1]:
                out.pop()  # "2 >" from "2>file"
            target = words[k + 1] if k + 1 < len(words) else ""
            if (w.startswith(">") or w.startswith("&")) and target != "/dev/null" \
                    and not re.fullmatch(r"\d+", target):
                writes = True
            skip = True
            continue
        out.append(w)
    return out, writes


ASSIGN_RE = re.compile(r"^([A-Za-z_]\w*)=(.*)$", re.S)


def joinWords(words):
    return " ".join(f"'{w}'" if (not w or re.search(r"\s", w)) else w for w in words)


# ---------------------------------------------------------------- analysis

class Part:
    """One guarded subcommand needing a rule."""

    def __init__(self, kind, match, desc, sha=None, sudo=None, preview=None):
        self.kind, self.match, self.desc = kind, match, desc
        self.sha, self.sudo, self.preview = sha, sudo, preview
        self.env = None  # None = here (currentEnv()); "ssh:[user@]host[:port]" for remote parts


class Ctx:
    def __init__(self, cwd, remote=False):
        self.cwd = cwd
        self.remote = remote       # analyzing a command that runs over ssh
        self.vars = {} if remote else {"HOME": HOME}
        self.allTrivial = True     # every unguarded part is ok
        self.parts = []            # guarded Parts
        self.heredocBodies = []
        self.sshHeredocs = []      # heredoc bodies whose command line mentions ssh
        self.nCommands = 0


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
    if (s == "~" or s.startswith("~/")) and not ctx.remote:
        s = HOME + s[1:]
    return s


def absPath(p, ctx):
    p = expandVars(p, ctx)
    if ctx.remote and p.startswith("~"):
        return p  # remote home: keep as written
    if not os.path.isabs(p):
        if ctx.cwd is None:
            raise Ask("relative path with unknown cwd")
        p = os.path.join(ctx.cwd, p)
    return os.path.normpath(p) if not (set(p) & GLOB_CHARS) else p


def isUnderRootRemote(path):
    """Remote paths can't be resolved; purely textual check against /tmp and ~/tmp."""
    globIdx = next((i for i, c in enumerate(path) if c in GLOB_CHARS), None)
    if globIdx is not None:
        head, rest = path[:globIdx], path[globIdx:]
        if ".." in rest.split("/"):
            return False
        # dir containing the glob must be strictly below a root
        target = os.path.normpath(head if head.endswith("/") else os.path.dirname(head))
    else:
        target = os.path.dirname(os.path.normpath(path)) + "/" + os.path.basename(os.path.normpath(path))
        target = os.path.normpath(target)
    return any(target.startswith(r + "/") for r in ("/tmp", "~/tmp"))


def isUnderRoot(path):
    """path: absolute, may contain a glob."""
    globIdx = next((i for i, c in enumerate(path) if c in GLOB_CHARS), None)
    if globIdx is not None:
        head, rest = path[:globIdx], path[globIdx:]
        if ".." in rest.split("/"):
            return False
        base = head if head.endswith("/") else os.path.dirname(head)
        target = os.path.realpath(base)
        # strictly below a root: "rm /tmp/*" would hit other programs' files
        return any(target.startswith(r + "/") for r in realRoots())
    norm = os.path.normpath(path)
    # don't follow the final component (rm removes the link, not its target)
    parent = os.path.realpath(os.path.dirname(norm))
    full = os.path.join(parent, os.path.basename(norm))
    return any(full.startswith(r + "/") for r in realRoots())


def sha(data):
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()[:20]


def addCmdPart(words, desc, ctx):
    ctx.parts.append(Part("cmd", joinWords(words), desc))


def checkRm(words, ctx, prefix=()):
    """words = ["rm", ...]. ok if every path is inside a scratch root, else a cmd Part
    with paths made absolute so the rule is cwd independent."""
    endOfOpts, flags, paths = False, [], []
    for a in words[1:]:
        if not endOfOpts and a == "--":
            endOfOpts = True
        elif not endOfOpts and a.startswith("-") and a != "-":
            flags.append(a)
        else:
            paths.append(a)
    try:
        absPaths = [absPath(p, ctx) for p in paths]
    except Ask as e:
        addCmdPart(list(prefix) + words, f"{words[0]}: {e}", ctx)
        return
    flagsOk = all(re.fullmatch(r"-[rRfvdI]+|--(recursive|force|verbose|dir)", f) for f in flags)
    if not paths:
        addCmdPart(list(prefix) + words, f"{words[0]} with no paths", ctx)
        return
    # one rule per path, like compound commands: each target can be allowed on its own.
    # Plain rm of scratch paths needs no rule; sudo rm always does.
    head = list(prefix) + [words[0]] + flags
    for p, a in zip(paths, absPaths):
        underRoot = isUnderRootRemote(a) if ctx.remote else isUnderRoot(a)
        if not prefix and flagsOk and underRoot:
            continue
        where = "" if prefix else " (outside /tmp, ~/tmp)"
        addCmdPart(head + [a], f"{joinWords(head)} {p}{where}", ctx)


def checkScriptFile(path, underSudo, ctx):
    try:
        with open(path, "rb") as f:
            content = f.read(16 * 1024 * 1024)
    except OSError:
        if underSudo:
            raise Ask(f"sudo script {path} not readable")
        ctx.allTrivial = False  # missing: it won't run; leave to rules
        return
    who = "sudo " if underSudo else ""
    ctx.parts.append(Part("script", path, f"{who}run of script {path}",
                          sha=sha(content), sudo=underSudo))


def interpFlags(name, which):
    """Per-interpreter flags: "inline" = next arg is code, "check" = syntax check only."""
    if name.startswith("python"):
        return {"inline": {"-c"}, "check": set()}[which]
    if name == "node":
        return {"inline": {"-e", "--eval", "-p", "--print"}, "check": {"-c", "--check"}}[which]
    if name == "perl":
        return {"inline": {"-e", "-E"}, "check": {"-c"}}[which]
    if name == "ruby":
        return {"inline": {"-e"}, "check": {"-c"}}[which]
    # shells
    return {"inline": {"-c"}, "check": {"-n"}}[which]


def checkScriptRun(name, args, ctx, underSudo, wordsForCmd):
    """name = interpreter basename. args after the interpreter."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "-":
        a = args[i]
        if a in interpFlags(name, "check"):
            # syntax check only: the file is parsed, not run
            if underSudo:
                addCmdPart(wordsForCmd, f"sudo {name} {a}", ctx)
            else:
                ctx.allTrivial = False
            return
        if a in interpFlags(name, "inline"):
            inline = args[i + 1] if i + 1 < len(args) else ""
            if name in SHELLS and INTEREST_RE.search(inline):
                analyzeScript(inline, ctx, 1)
            if underSudo:
                ctx.parts.append(Part("inline", sha(inline), f"sudo {name} inline script",
                                      sudo=True, preview=inline[:200]))
            else:
                ctx.allTrivial = False
            return
        if a == "-m" or a in ("-V", "--version", "-v", "--help", "-h"):
            if underSudo:
                addCmdPart(wordsForCmd, f"sudo {name} {a}", ctx)
            else:
                ctx.allTrivial = False
            return
        if a in ("-W", "-X", "-r", "--require", "--import", "--loader") and i + 1 < len(args):
            i += 1  # option with a value
        i += 1
    rest = args[i:]
    if not rest or rest[0] == "-":
        # program on stdin (heredoc / pipe)
        if underSudo:
            body = "\n".join(ctx.heredocBodies)
            if not body:
                raise Ask(f"sudo {name} reading stdin")
            ctx.parts.append(Part("inline", sha(body), f"sudo {name} heredoc script",
                                  sudo=True, preview=body[:200]))
        else:
            ctx.allTrivial = False
        return
    if ctx.remote:
        # can't hash a file on another machine: exact-command rule instead
        addCmdPart(wordsForCmd, f"remote script run {rest[0]}", ctx)
        return
    try:
        path = os.path.realpath(absPath(rest[0], ctx))
    except Ask as e:
        if underSudo:
            raise
        ctx.allTrivial = False
        return
    checkScriptFile(path, underSudo, ctx)


def isDirectExec(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def containerRunKey(tool, sub, args):
    """Normalized 'tool run <security flags> IMAGE <command...>'."""
    kept, i = [], 0
    while i < len(args):
        a = args[i]
        if not a.startswith("-"):
            break
        flag, val = (a.split("=", 1) + [None])[:2] if a.startswith("--") and "=" in a else (a, None)
        if flag in RUN_KEEP_FLAGS:
            kept.append(flag)
        elif flag in RUN_KEEP_NETWORK_HOST or flag in RUN_KEEP_VALUE or flag in RUN_DROP_VALUE:
            if val is None:
                i += 1
                val = args[i] if i < len(args) else ""
            if flag in RUN_KEEP_NETWORK_HOST:
                if val == "host":
                    kept.append(f"{flag}=host")
            elif flag in RUN_KEEP_VALUE:
                kept.append(f"{flag} {val}" if not flag.startswith("--") else f"{flag}={val}")
            # else dropped
        elif re.fullmatch(r"-[a-zA-Z]+", a) and not set(a[1:]) - set("itd"):
            pass  # -it / -d / -i
        elif flag in RUN_BOOL_FLAGS:
            pass
        elif a.startswith("--") and val is None and i + 1 < len(args) and not args[i + 1].startswith("-"):
            # unknown long flag: assume it takes the next word as its value, keep both
            i += 1
            kept.append(f"{a}={args[i]}")
        else:
            kept.append(a)  # unknown flag: keep it, safer
        i += 1
    rest = args[i:]
    return " ".join([tool, sub] + sorted(kept) + [joinWords(rest)]).strip()


def checkContainer(words, ctx, sudoPrefix):
    tool = os.path.basename(words[0])
    args = words[1:]
    # skip global options (podman --root x, docker --context y)
    while args and args[0].startswith("-"):
        args = args[2:] if args[0] in ("--context", "-c", "--root", "--runroot", "-H", "--host") else args[1:]
    if not args:
        ctx.allTrivial = False
        return
    sub = args[0]
    if sub == "compose" or tool.endswith("compose"):
        cargs = [a for a in args[1:] if not a.startswith("-")] if sub == "compose" else args
        csub = next((a for a in cargs if a in COMPOSE_READONLY | {"down", "rm", "up", "run",
                                                                   "exec", "build", "pull",
                                                                   "push", "stop", "kill"}), "")
        if csub in COMPOSE_READONLY and not sudoPrefix:
            return
        if (csub == "down" and ("-v" in args or "--volumes" in args)) or csub in ("rm", "push", "kill"):
            addCmdPart(list(sudoPrefix) + words, f"{tool} compose {csub}", ctx)
            return
        if sudoPrefix:
            addCmdPart(list(sudoPrefix) + words, f"sudo {tool} compose {csub}", ctx)
            return
        ctx.allTrivial = False
        return
    if sub == "container" and len(args) > 1:
        args = args[1:]
        sub = args[0]
    prefix = "sudo " if sudoPrefix else ""
    if sub in ("run", "create"):
        key = prefix + containerRunKey(tool, sub, args[1:])
        ctx.parts.append(Part("container", key, f"{prefix}{tool} {sub}",
                              sudo=bool(sudoPrefix)))
        return
    if sub in CONTAINER_READONLY or (sub in ("image", "volume", "network", "system")
                                     and len(args) > 1 and args[1] in ("ls", "inspect", "df")):
        if sudoPrefix:
            addCmdPart(list(sudoPrefix) + words, f"sudo {tool} {sub}", ctx)
        return
    if sub in CONTAINER_DESTRUCTIVE or (len(args) > 1 and args[1] in ("rm", "prune")) or sudoPrefix:
        addCmdPart(list(sudoPrefix) + words, f"{prefix}{tool} {sub}", ctx)
        return
    if sub == "exec" and any(a in ("--privileged", "-u", "--user") for a in args):
        addCmdPart(words, f"{tool} exec as other user/privileged", ctx)
        return
    ctx.allTrivial = False


# wrappers that only adjust how a command runs; stripped (with their options) so rules
# key on the wrapped command. e.g. the timeout duration changes every call.
SIMPLE_WRAPPERS = {
    # name: (options that take a value, pattern for positional args before the command)
    "timeout": ({"-s", "--signal", "-k", "--kill-after"}, re.compile(r"[\d.]+[smhd]?")),
    "nice": ({"-n", "--adjustment"}, None),
    "ionice": ({"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "-u"}, None),
    "stdbuf": ({"-i", "-o", "-e", "--input", "--output", "--error"}, None),
    "nohup": (set(), None),
    "setsid": (set(), None),  # new session / detached from the terminal; no privilege change
    "time": ({"-f", "--format", "-o", "--output"}, None),
    "command": (set(), None),
    "env": ({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}, None),
}


def stripWrappers(words):
    """Drop leading SIMPLE_WRAPPERS and their options; returns the wrapped command."""
    while words and os.path.basename(words[0]) in SIMPLE_WRAPPERS:
        name = os.path.basename(words[0])
        valueOpts, positional = SIMPLE_WRAPPERS[name]
        i = 1
        while i < len(words):
            w = words[i]
            if w == "--":
                i += 1
                break
            if w.startswith("-") and len(w) > 1:
                i += 2 if (w in valueOpts and "=" not in w) else 1
            elif name == "env" and ASSIGN_RE.match(w):
                i += 1
            elif name == "nice" and re.fullmatch(r"-?\d+", w):
                i += 1
            else:
                break
        if positional is not None and i < len(words) and positional.fullmatch(words[i]):
            i += 1  # timeout DURATION
        words = words[i:]
    return words


SSH_VALUE_OPTS = set("BbcDEeFIiJLlmOoPpQRSWw")
SSH_FORWARD_OPTS = set("LRDWwO")  # forwarding / control: not a plain remote command
SSH_LOCAL_EXEC_OPTIONS = re.compile(r"^(proxycommand|localcommand|permitlocalcommand|remotecommand|"
                                    r"proxyusefdpass|knownhostscommand)\b", re.I)


def checkSsh(words, ctx, depth):
    """ssh [opts] [user@]host [cmd...]: analyze cmd (or a heredoc script on stdin) as a
    remote command whose parts get env "ssh:[user@]host[:port]"."""
    args = words[1:]
    user = port = None
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "-":
        a = args[i]
        if a == "--":
            i += 1
            break
        j = 1
        while j < len(a):
            c = a[j]
            if c in SSH_VALUE_OPTS:
                val = a[j + 1:] or (args[i + 1] if i + 1 < len(args) else "")
                if not a[j + 1:]:
                    i += 1
                if c in SSH_FORWARD_OPTS:
                    addCmdPart(words, f"ssh -{c} (forwarding/control)", ctx)
                    return
                if c == "o" and SSH_LOCAL_EXEC_OPTIONS.match(val):
                    addCmdPart(words, f"ssh -o {val.split('=')[0]} runs a local command", ctx)
                    return
                if c == "l":
                    user = val
                if c == "p":
                    port = val
                break
            if c == "N":
                addCmdPart(words, "ssh -N (no remote command)", ctx)
                return
            j += 1
        i += 1
    if i >= len(args):
        raise Ask("ssh with no host")
    host = args[i]
    if "@" in host:
        user, host = host.rsplit("@", 1)
    rest = args[i + 1:]
    env = "ssh:" + (f"{user}@" if user else "") + host + (f":{port}" if port else "")

    if not rest or (os.path.basename(rest[0]) in SHELLS and not ({"-c"} & set(rest[1:]))):
        # interactive, or a shell reading its script from stdin (heredoc)
        if not ctx.sshHeredocs:
            addCmdPart(words, f"interactive ssh to {host}", ctx)
            return
        script = "\n".join(ctx.sshHeredocs)
    else:
        script = " ".join(rest)  # ssh joins the remaining args with spaces

    rctx = Ctx(None, remote=True)
    analyzeScript(script, rctx, depth + 1)
    for p in rctx.parts:
        p.env = env
    ctx.parts += rctx.parts
    if not rctx.allTrivial:
        ctx.allTrivial = False


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


def checkSudo(words, ctx):
    args = words[1:]
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] not in SUDO_OK_FLAGS:
            addCmdPart(words, f"sudo {args[i]}", ctx)
            return
        i += 1
    rest = args[i:]
    if not rest:
        raise Ask("bare sudo")
    while rest and ASSIGN_RE.match(rest[0]):
        rest = rest[1:]  # sudo VAR=x cmd: key keeps them via words
    if not rest:
        raise Ask("sudo with only assignments")
    sudoPrefix = words[:len(words) - len(rest)]
    rest = stripWrappers(rest)  # sudo timeout 30 cmd -> sudo cmd
    if not rest:
        raise Ask("sudo wrapper with no command")
    words = sudoPrefix + rest
    name = os.path.basename(rest[0])
    if INTERP_RE.match(name):
        checkScriptRun(name, rest[1:], ctx, True, words)
        return
    if name in ("rm", "rmdir"):
        checkRm(rest, ctx, prefix=sudoPrefix)
        return
    if name in CONTAINER_TOOLS:
        checkContainer(rest, ctx, sudoPrefix)
        return
    if name in ("pkill", "killall"):
        target = [a for a in rest[1:] if not a.startswith("-")]
        fFlag = "-f" in rest[1:] or "--full" in rest[1:]
        if len(target) == 1 and not (set(target[0]) & set("$`")):
            ctx.parts.append(Part("pkill", ("-f " if fFlag else "") + target[0],
                                  f"sudo {name} {target[0]}", sudo=True))
            return
        addCmdPart(words, f"sudo {name}", ctx)
        return
    if name in SAFE_SUDO:
        bad = SAFE_SUDO_BAD_ARGS.get(name)
        if not (bad and any(bad.search(a) for a in rest[1:])) \
                and not any("$(" in a or "`" in a for a in rest[1:]):
            return
    addCmdPart(words, f"'sudo {name}' is not on the read-only sudo list", ctx)


def analyzeCommand(words, ctx, depth):
    words, writesFile = stripRedirects(words)
    while words and ASSIGN_RE.match(words[0]):
        k, v = ASSIGN_RE.match(words[0]).groups()
        try:
            ctx.vars[k] = expandVars(v, ctx)
        except Ask:
            ctx.vars.pop(k, None)  # unknown value; using it later will Ask
        words = words[1:]
    if not words:
        return
    if writesFile:
        ctx.allTrivial = False
    name = os.path.basename(words[0])
    args = words[1:]

    if name in SIMPLE_WRAPPERS:
        inner = stripWrappers(words)
        if inner:
            analyzeCommand(inner, ctx, depth)
        return

    if name in EXEC_WRAPPERS:
        j = 0
        while j < len(args) and (args[j].startswith("-") or ASSIGN_RE.match(args[j])
                                 or (name == "timeout" and re.fullmatch(r"[\d.]+[smhd]?", args[j]))):
            j += 1
        if name in ("xargs", "watch", "flock") and any(INTEREST_RE.search(a) for a in args):
            raise Ask(f"{name} running a guarded command")
        if args[j:]:
            analyzeCommand(args[j:], ctx, depth)
        return

    if name in SHELLS and "-c" not in args:
        checkScriptRun(name, args, ctx, False, words)
        return
    if name in SHELLS:
        k = args.index("-c")
        script = args[k + 1] if k + 1 < len(args) else ""
        if INTEREST_RE.search(script):
            if depth > 3:
                raise Ask("nesting too deep")
            analyzeScript(script, ctx, depth + 1)
        ctx.allTrivial = False
        return

    if name == "ssh":
        checkSsh(words, ctx, depth)
        return

    if name == "eval":
        if any(INTEREST_RE.search(a) for a in args):
            raise Ask("eval of a guarded command")
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
            ctx.cwd = os.path.normpath(os.path.join(ctx.cwd, t)) if ctx.cwd \
                else (t if os.path.isabs(t) else None)
        except Ask:
            ctx.cwd = None
        return

    if name in ("rm", "rmdir"):
        checkRm(words, ctx)
        return
    if name == "sudo":
        checkSudo(words, ctx)
        return
    if name in CONTAINER_TOOLS or name in ("docker-compose", "podman-compose"):
        checkContainer(words, ctx, ())
        return
    if INTERP_RE.match(name):
        checkScriptRun(name, args, ctx, False, words)
        return
    if "/" in words[0] and ctx.cwd is not None and not ctx.remote:
        p = os.path.join(ctx.cwd, os.path.expanduser(words[0]))
        if isDirectExec(p):
            checkScriptFile(os.path.realpath(p), False, ctx)
            return

    if name not in TRIVIAL:
        ctx.allTrivial = False


def analyzeScript(cmd, ctx, depth=0):
    cmd, bodies = stripHeredocs(cmd)
    ctx.heredocBodies += [b for _, b in bodies]
    ctx.sshHeredocs += [b for line, b in bodies if re.search(r"\bssh\b", line)]
    for line, body in bodies:
        if re.search(r"(^|[^\w.-])(sudo|rm|rmdir)(\s|$)", body) \
                and re.search(r"(^|[\s;&|(])(bash|sh|zsh|dash|sudo)\b", line) \
                and not re.search(r"\bssh\b", line):
            raise Ask("heredoc shell script containing sudo/rm")
    for sub in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", cmd):
        s = sub[0] or sub[1]
        if INTEREST_RE.search(s):
            analyzeScript(s, ctx, depth + 1)
            ctx.allTrivial = False
    cmds = splitCommands(tokenize(cmd))
    if depth == 0:
        ctx.nCommands += len(cmds)
    for words in cmds:
        analyzeCommand(words, ctx, depth)


# ---------------------------------------------------------------- rules file

def nowText():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def projectOf(cwd):
    d = cwd or "/"
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return cwd or "/"
        d = parent


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
    if part.kind == "container":
        return containerMatches(rule.get("match", ""), part.match)
    return textMatches(rule.get("match", ""), part.match)


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
    if any(r.get("decision") == "deny" and ruleMatches(r, part, session, project) for r in rules):
        return "deny"
    best, bestKey = None, None
    for r in rules:
        if r.get("decision") not in ("allow", "ask") or not ruleMatches(r, part, session, project):
            continue
        k = specificity(r)
        if bestKey is None or k > bestKey or (k == bestKey and r.get("decision") == "ask"):
            best, bestKey = r.get("decision"), k
    return best


VALUE_SHORT_FLAGS = {"-v", "-u"}


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


def short(s, n=60):
    return s if len(s) <= n else s[:n - 1] + "…"


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
    HOST_ALIASES[:] = [{k.lower(), *(x.lower() for x in v)} for k, v in hosts.items()]
    for i, r in enumerate(data["rules"]):
        if not isinstance(r, dict) or not isinstance(r.get("kind"), str) \
                or not isinstance(r.get("match"), str):
            raise RulesFileError(f'rules[{i}] needs string "kind" and "match"')
        if r.get("decision") not in ("allow", "ask", "deny"):
            raise RulesFileError(f'rules[{i}] "decision" must be "allow", "ask" or "deny"')
        if r.get("match", "").startswith("re:"):
            try:
                re.compile(r["match"][3:])
            except re.error as e:
                raise RulesFileError(f"rules[{i}] bad regex: {e}")
    for i, p in enumerate(data["pending"]):
        if not isinstance(p, dict) or not isinstance(p.get("rules"), list) \
                or not all(isinstance(r, dict) for r in p["rules"]):
            raise RulesFileError(f'pending[{i}] needs a "rules" list of objects')
    return data


def loadRules():
    """Returns the rules data. Raises RulesFileError if the file can't be used;
    a missing file is just empty."""
    try:
        with open(RULES_PATH) as f:
            data = json.load(f)
    except FileNotFoundError:
        return emptyRules()
    except ValueError as e:
        raise RulesFileError(f"invalid JSON: {e}")
    except OSError as e:
        raise RulesFileError(f"can't read: {e}")
    return validateRules(data)


# While the rules file is broken, new pending entries and approvals go here; they are
# merged into the rules file the next time it loads cleanly.
RECOVERY_PATH = os.path.join(HOOK_DIR, "sudoRmGuard-rules.recovery.json")


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
    """Indented, fixed key order so the file is easy to hand-edit; sorted by date."""
    data["rules"] = cleanupRules(data["rules"])
    order = ["decision", "kind", "match", "sha", "sudo", "session", "path", "env", "at", "from", "preview",
             "toolUseId", "cmd", "rules"]

    def ordered(r):
        out = {k: r[k] for k in order if k in r}
        out.update({k: v for k, v in r.items() if k not in out})
        if "rules" in out:
            out["rules"] = [ordered(x) for x in out["rules"]]
        return out
    text = json.dumps({
        "hosts": data.get("hosts", {}),
        "rules": [ordered(r) for r in sorted(data["rules"], key=lambda r: r.get("at", ""))],
        "pending": [ordered(p) for p in sorted(data["pending"], key=lambda p: p.get("at", ""))],
    }, indent=2, ensure_ascii=False) + "\n"
    tmp = RULES_PATH + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, RULES_PATH)


def prunePending(pending):
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - PENDING_TTL))
    pending = [p for p in pending if p.get("at", "") >= cutoff]
    return sorted(pending, key=lambda p: p.get("at", ""))[-PENDING_MAX:]


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


def decide(cmd, cwd, session="", data=None):
    """Returns (decision or None, reason, proposedRules)."""
    if not INTEREST_RE.search(cmd):
        return None, "nothing guarded", []
    data = data if data is not None else loadRules()
    project = projectOf(cwd)
    ctx = Ctx(cwd)
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
    if asks:
        return "ask", "sudo/rm guard: " + shapeNote(cmd, ctx) + "; ".join(asks), proposals
    if ctx.allTrivial:
        return "allow", "sudo/rm guard: all guarded parts allowed", []
    return None, "sudo/rm guard: guarded parts allowed; rest left to rules", []


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


def handlePre(data):
    cmd = (data.get("tool_input") or {}).get("command", "")
    session = data.get("session_id", "")
    tid = data.get("tool_use_id")
    with Lock():
        rules, err = openRules()
    if err:
        # unusable rules file: ask about everything, but still record what we'd propose
        # so an approval now can be learned once the file is fixed
        _, reason, proposals = decide(cmd, data.get("cwd"), session, emptyRules())
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
        decision, reason, proposals = decide(cmd, data.get("cwd"), session, rules)
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
            d, reason, props = decide(sys.argv[2], cwd, "test")
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
    if data.get("tool_name") != "Bash":
        return
    if data.get("hook_event_name", "").startswith("PostToolUse"):
        handlePost(data)
        return
    try:
        handlePre(data)
    except Exception as e:  # never let a crash fall through to "no decision"
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": f"sudo/rm guard crashed ({type(e).__name__}: {e}); asking to be safe",
        }}))


if __name__ == "__main__":
    main()
