"""z-agent-guard: parse (moved verbatim from the single-file hook)."""
import os
import re
import shlex

from .defaults import ASSIGN_RE, NOISE_REDIRECT_RE, OPS, SIMPLE_WRAPPERS, STD_BIN_DIRS


class Ask(Exception):
    pass


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


def joinWords(words):
    return " ".join(f"'{w}'" if (not w or re.search(r"\s", w)) else w for w in words)


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
    if words and os.path.dirname(words[0]) in STD_BIN_DIRS:
        words = [os.path.basename(words[0])] + words[1:]  # /usr/bin/chroot -> chroot
    return words


def commandSubstitutions(args):
    """Bodies of $(...) in args, or None if there are backticks or unbalanced parens."""
    out = []
    for a in args:
        if "`" in a:
            return None
        i = a.find("$(")
        while i >= 0:
            depth, j = 0, i + 1
            while j < len(a):
                depth += {"(": 1, ")": -1}.get(a[j], 0)
                if depth == 0:
                    break
                j += 1
            if depth:
                return None
            out.append(a[i + 2:j])
            i = a.find("$(", j)
    return out
