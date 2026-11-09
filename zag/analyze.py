"""z-agent-guard: analyze (moved verbatim from the single-file hook)."""
import os
import re

from .defaults import ASSIGN_RE, COMPOSE_READONLY, CONTAINER_DESTRUCTIVE, CONTAINER_READONLY, CONTAINER_TOOLS, EXEC_WRAPPERS, GIT_KEYWORD, GIT_READONLY, GIT_RISKY, GIT_VALUE_OPTS, GLOB_CHARS, GUARDED, HOME, INTEREST_RE, INTERP_RE, RUN_BOOL_FLAGS, RUN_DROP_VALUE, RUN_KEEP_FLAGS, RUN_KEEP_NETWORK_HOST, RUN_KEEP_VALUE, SAFE_SUDO, SAFE_SUDO_BAD_ARGS, SCRATCH_ROOTS, SHELLS, SIMPLE_WRAPPERS, SSH_FORWARD_OPTS, SSH_LOCAL_EXEC_OPTIONS, SSH_VALUE_OPTS, SUDO_OK_FLAGS, TRIVIAL
from .util import sha
from .parse import Ask, commandSubstitutions, joinWords, splitCommands, stripHeredocs, stripRedirects, stripWrappers, tokenize
from .rules import ruleMatches, textMatches


# ---------------------------------------------------------------- parsing

def isDenied(part, ctx):
    """Whether a deny rule matches part (deny always wins, even where no rule is needed)."""
    return any(r.get("decision") == "deny" and ruleMatches(r, part, ctx.session, ctx.project)
               for r in ctx.rules)


def realRoots():
    return [os.path.realpath(r) for r in SCRATCH_ROOTS]


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
        self.gitAuth = set()       # {"commit", "push"} authorized by the user's last message
        self.gitAsks = []          # git add/commit/push not authorized
        self.grantCmds = []        # session-granted command patterns
        self.rules = []
        self.session = ""
        self.project = None


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
    if set(p) & GLOB_CHARS:
        return p
    # keep a trailing "/" : "rm -r link/" descends into the link's target
    return os.path.normpath(p) + ("/" if re.search(r"/\.?$", p) and p.strip("/") else "")


def belowTmp(path):
    """True if path is strictly inside a directory named tmp (/tmp/x, /var/tmp/x,
    /var/tmp/chroot/tmp/x, ~/tmp/x), not the tmp dir itself."""
    parts = [p for p in path.split("/") if p]
    return any(c == "tmp" for c in parts[:-1])


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
    return belowTmp(target) and ".." not in target.split("/")


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
        return any(target.startswith(r + "/") for r in realRoots()) or belowTmp(target)
    norm = os.path.normpath(path)
    if re.search(r"/\.?$", path):
        # "link/" makes rm -r descend into the link's target: judge the target
        full = os.path.realpath(norm)
    else:
        # don't follow the final component (rm removes the link, not its target)
        parent = os.path.realpath(os.path.dirname(norm))
        full = os.path.join(parent, os.path.basename(norm))
    return any(full.startswith(r + "/") for r in realRoots()) or belowTmp(full)


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
    # [sudo] rm of anything inside a */tmp/ dir (symlinks resolved) needs no rule.
    head = list(prefix) + [words[0]] + flags
    for p, a in zip(paths, absPaths):
        underRoot = isUnderRootRemote(a) if ctx.remote else isUnderRoot(a)
        if flagsOk and underRoot and not isDenied(Part("cmd", joinWords(head + [a]), ""), ctx):
            continue  # deny rules still win inside tmp dirs
        where = " (not inside a tmp dir)" if flagsOk else ""
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
        positional = [a for a in rest[1:] if not a.startswith("-")]
        if (bad and any(bad.search(a) for a in rest[1:])) or \
                (name in ("xxd", "uniq") and len(positional) > 1):  # 2nd positional = output file
            addCmdPart(words, f"'sudo {name}' with arguments that can write", ctx)
            return
        if any("`" in a for a in rest[1:]) or commandSubstitutions(rest[1:]) is None:
            addCmdPart(words, f"'sudo {name}' with a command substitution the guard can't parse", ctx)
        # $(...) bodies are judged on their own by analyzeScript
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
    if ctx.grantCmds and not ctx.remote:
        text = joinWords(words)
        if any(textMatches(p, text) for p in ctx.grantCmds) and \
                not isDenied(Part("cmd", text, ""), ctx):
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

    if name == "git":
        checkGit(args, ctx)
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
def checkGit(args, ctx):
    """git subcommands in GIT_KEYWORD need their keyword (e.g. "Commit") in the user's last
    message; read-only ones are fine; anything else is left to settings rules."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in GIT_VALUE_OPTS else 1
    sub, rest = (args[i], args[i + 1:]) if i < len(args) else (None, [])
    if not ctx.remote and sub in GIT_READONLY:
        return
    if ctx.remote or sub not in GIT_KEYWORD:
        ctx.allTrivial = False
        return
    need = GIT_KEYWORD[sub]
    risky = GIT_RISKY.get(sub)
    if need not in ctx.gitAuth:
        ctx.gitAsks.append(f"git {sub} (not authorized: type '{need.capitalize()}' mid-sentence)")
    elif risky and any(risky.match(a) for a in rest):
        ctx.gitAsks.append(f"git {sub} with risky args")
    elif sub == "checkout" and (ctx.cwd is None or any(
            not a.startswith("-") and os.path.exists(os.path.join(ctx.cwd, a)) for a in rest)):
        ctx.gitAsks.append("git checkout of a path (discards changes)")


def analyzeScript(cmd, ctx, depth=0):
    cmd, bodies = stripHeredocs(cmd)
    ctx.heredocBodies += [b for _, b in bodies]
    ctx.sshHeredocs += [b for line, b in bodies if re.search(r"\bssh\b", line)]
    for line, body in bodies:
        if re.search(r"(^|[^\w.-])(sudo|rm|rmdir)(\s|$)", body) \
                and re.search(r"(^|[\s;&|(])(bash|sh|zsh|dash|sudo)\b", line) \
                and not re.search(r"\bssh\b", line):
            raise Ask("heredoc shell script containing sudo/rm")
    subs = re.findall(r"\$\(([^()]*)\)|`([^`]*)`", cmd)
    if len(subs) < cmd.count("$(") + cmd.count("`") // 2:
        ctx.allTrivial = False  # nested/unparsed substitution: leave to settings rules
    for sub in subs:
        # judged like any other command: a trivial one ($(ls x | head -1)) keeps allTrivial
        if depth > 3:
            raise Ask("nesting too deep")
        analyzeScript(sub[0] or sub[1], ctx, depth + 1)
    cmds = splitCommands(tokenize(cmd))
    if depth == 0:
        ctx.nCommands += len(cmds)
    for words in cmds:
        analyzeCommand(words, ctx, depth)
