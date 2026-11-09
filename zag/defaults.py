"""z-agent-guard: defaults (moved verbatim from the single-file hook)."""
import os
import re


HOME = os.path.expanduser("~")
PENDING_TTL = 2 * 3600
PENDING_MAX = 50
SCRATCH_ROOTS = ["/tmp", os.path.join(HOME, "tmp")]

INTERP_RE = re.compile(r"^(python[\d.]*|node|perl|ruby|bash|sh|zsh|dash)$")
# cheap pre-filter: commands that can't contain anything guarded skip analysis
INTEREST_RE = re.compile(
    r"(^|[^\w.-])(sudo|rm|rmdir|docker|podman|ssh|git|python[\d.]*|node|perl|ruby|bash|sh|zsh|dash)(\s|$|;|\))"
    r"|(^|[\s;&|(])\.?\.?/[\w./-]+")

# sudo <cmd>: read-only commands, with args that would make them write rejected
SAFE_SUDO = {"ls", "cat", "grep", "egrep", "zgrep", "head", "tail", "dmesg", "journalctl",
             "strings", "objdump", "readelf", "pgrep", "stat", "file", "wc", "du", "lsof",
             "ss", "lsblk", "blkid", "xxd", "hexdump", "od", "md5sum", "sha256sum", "id", "true",
             "dmidecode",
             # more read-only tools (write-capable options are in SAFE_SUDO_BAD_ARGS)
             "find", "readlink", "realpath", "tree", "cmp", "diff", "sha1sum", "sha512sum",
             "b2sum", "cksum", "base64", "nl", "tac", "rg", "fgrep", "zcat", "xzcat", "bzcat",
             "zstdcat", "lsattr", "getfacl", "getfattr", "getcap", "lspci", "lsusb", "lsmod",
             "lscpu", "lsns", "nm", "jq", "column", "cut", "sort", "uniq", "df", "findmnt",
             "ps", "pidof", "netstat", "whoami", "groups", "uname", "uptime", "free",
             "basename", "dirname", "test", "[", "printenv", "sensors", "dumpe2fs", "debugfs"}
SAFE_SUDO_BAD_ARGS = {
    "find": re.compile(r"^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$"),
    "sort": re.compile(r"^(-o.*|--output.*)$"),
    "tree": re.compile(r"^(-o.*|--output.*)$"),
    "debugfs": re.compile(r"^-\w*w"),  # opens read-only unless -w
    "diff": re.compile(r"^--?(output|to-file|from-file)"),
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


# fd plumbing that doesn't change what a command does: 2>&1, 2>/dev/null, &>/dev/null
NOISE_REDIRECT_RE = re.compile(r"(?<!\S)(\d*>&\d+|&?\d*>>?\s*/dev/null)(?=\s|$|[;&|)])")


ASSIGN_RE = re.compile(r"^([A-Za-z_]\w*)=(.*)$", re.S)


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


# system dirs on sudo's secure_path: "/usr/bin/x" is the same command as "x"
STD_BIN_DIRS = {"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}


SSH_VALUE_OPTS = set("BbcDEeFIiJLlmOoPpQRSWw")
SSH_FORWARD_OPTS = set("LRDWwO")  # forwarding / control: not a plain remote command
SSH_LOCAL_EXEC_OPTIONS = re.compile(r"^(proxycommand|localcommand|permitlocalcommand|remotecommand|"
                                    r"proxyusefdpass|knownhostscommand)\b", re.I)


GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
# subcommand -> keyword that authorizes it (typed capitalized mid-sentence)
GIT_KEYWORD = {"add": "commit", "commit": "commit", "push": "push", "branch": "branch",
               "checkout": "branch", "switch": "branch", "stash": "stash", "fetch": "fetch",
               "pull": "pull", "rebase": "rebase", "merge": "merge", "tag": "tag",
               "remote": "remote"}
# read-only; allowed alongside any authorized part
GIT_READONLY = {"status", "log", "diff", "show", "blame", "rev-parse", "shortlog", "ls-files",
                "merge-base", "describe", "rev-list", "ls-remote", "cat-file", "whatchanged"}
# risky args per subcommand: always ask, even when authorized
GIT_RISKY = {
    "push": re.compile(r"^(-f|--force.*|--delete|-d|--mirror|--prune|--all|--tags|\+.*|:.*|.*:\+?)$"),
    "branch": re.compile(r"^(-D|-d|--delete|-f|--force|-M|-C)$"),
    "checkout": re.compile(r"^(-f|--force|-B|--orphan|\.|--)$"),
    "switch": re.compile(r"^(-f|--force|--discard-changes|-C|--force-create|--orphan)$"),
    "stash": re.compile(r"^(drop|clear)$"),
    "fetch": re.compile(r"^(--prune.*|-p|-P|--force|-f|\+.*)$"),
    "pull": re.compile(r"^(--force|-f|--rebase=i.*|-r=i.*)$"),
    "rebase": re.compile(r"^(-i|--interactive|--exec|-x|--root)$"),
    "tag": re.compile(r"^(-d|--delete|-f|--force)$"),
    "remote": re.compile(r"^(remove|rm|set-url|rename|prune)$"),
}


GIT_KEYWORDS = sorted({k.capitalize() for k in GIT_KEYWORD.values()})
# Keyword, Keyword* (session grant) or Keyword-* (session revoke)
GIT_AUTH_RE = re.compile(r"(?<![A-Za-z])(" + "|".join(GIT_KEYWORDS) + r")(-\*|\*)?(?![A-Za-z])")
GIT_MARKER_RE = re.compile(r"(?<![A-Za-z])(" + "|".join(GIT_KEYWORDS) + r")(-\*|\*)(?![A-Za-z])")
# [command pattern]* / [command pattern]-*  (only in a markers-only prompt)
CMD_GRANT_RE = re.compile(r"\[([^\[\]]+)\](-\*|\*)")
GRANT_TTL_DAYS = 14
USAGE_FIELDS = ("lastUsed", "uses", "supersededBy", "archivedAt")  # not part of a rule's identity


VALUE_SHORT_FLAGS = {"-v", "-u"}
MAINT_INTERVAL = 3600
SPLIT_MIN = 20
ARCHIVE_IDLE_DAYS = 30          # unused this long and used < ARCHIVE_MAX_USES times
ARCHIVE_MAX_USES = 3
ARCHIVED_SESSION_IDLE_DAYS = 7  # rule of a session archived in the desktop app


RULE_KEY_ORDER = ["decision", "kind", "match", "sha", "sudo", "session", "path", "env", "at",
                  "lastUsed", "uses", "supersededBy", "archivedAt", "from", "preview",
                  "toolUseId", "cmd", "rules"]


# per-machine overrides from config.json
from .config import applyOverrides  # noqa: E402
applyOverrides(globals())
