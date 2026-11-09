"""Locate the per-machine config directory and load config.json.

Layout (live install):
    ~/.claude/z-agent-guard/app/              this repo (code)
    ~/.claude/z-agent-guard/configs/<name>/   config.json + rules data

The config dir is, in order:
  1. $ZAG_CONFIG (a directory)
  2. configs/$ZAG_PROFILE
  3. configs/<hostname>, if it exists
  4. configs/default, if it exists
  5. the only directory in configs/, if there is exactly one (e.g. inside a devcontainer
     whose hostname is random, with ~/.claude bind-mounted)
  6. configs/<hostname> (created on first save)

"configs/" is next to the app dir when the app is installed as .../z-agent-guard/app,
otherwise ~/.claude/z-agent-guard/configs (e.g. when run from a dev checkout).

Only the standard library; must not import other zag modules (defaults imports this).
"""
import json
import os
import socket

APP_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
CONFIG_FILE_NAME = "config.json"


def configsRoot():
    parent = os.path.dirname(APP_DIR)
    if os.path.basename(APP_DIR) == "app" and os.path.isdir(os.path.join(parent, "configs")):
        return os.path.join(parent, "configs")
    return os.path.join(os.path.expanduser("~"), ".claude", "z-agent-guard", "configs")


def findConfigDir():
    if os.environ.get("ZAG_CONFIG"):
        return os.path.abspath(os.path.expanduser(os.environ["ZAG_CONFIG"]))
    root = configsRoot()
    if os.environ.get("ZAG_PROFILE"):
        return os.path.join(root, os.environ["ZAG_PROFILE"])
    host = socket.gethostname() or "default"
    for name in (host, "default"):
        if os.path.isdir(os.path.join(root, name)):
            return os.path.join(root, name)
    try:
        dirs = [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]
    except OSError:
        dirs = []
    if len(dirs) == 1:
        return os.path.join(root, dirs[0])
    return os.path.join(root, host)


CONFIG_DIR = findConfigDir()
CONFIG_ERROR = None  # set when config.json exists but can't be used


def loadConfig():
    global CONFIG_ERROR
    path = os.path.join(CONFIG_DIR, CONFIG_FILE_NAME)
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("top level must be an object")
        return data
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        CONFIG_ERROR = f"{path}: {e}"
        return {}


CONFIG = loadConfig()

# config.json key -> defaults.py name. Lists extend the built-in set; numbers/strings replace.
EXTEND = {
    "readOnlySudo": "SAFE_SUDO",
    "trivialCommands": "TRIVIAL",
    "scratchRoots": "SCRATCH_ROOTS",
}
REPLACE = {
    "pendingTtlSeconds": "PENDING_TTL",
    "pendingMax": "PENDING_MAX",
    "grantTtlDays": "GRANT_TTL_DAYS",
    "maintenanceIntervalSeconds": "MAINT_INTERVAL",
    "folderFileMinRules": "SPLIT_MIN",
    "archiveIdleDays": "ARCHIVE_IDLE_DAYS",
    "archiveMaxUses": "ARCHIVE_MAX_USES",
    "archivedSessionIdleDays": "ARCHIVED_SESSION_IDLE_DAYS",
}


def applyOverrides(ns):
    """Apply config.json to the defaults module's globals (called from defaults.py)."""
    global CONFIG_ERROR
    for key, name in EXTEND.items():
        extra = CONFIG.get(key)
        if extra is None:
            continue
        if not isinstance(extra, list) or not all(isinstance(x, str) for x in extra):
            CONFIG_ERROR = f'{CONFIG_FILE_NAME}: "{key}" must be a list of strings'
            continue
        cur = ns[name]
        ns[name] = cur | set(extra) if isinstance(cur, set) else list(cur) + [os.path.expanduser(x) for x in extra]
    for key, name in REPLACE.items():
        val = CONFIG.get(key)
        if val is None:
            continue
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            CONFIG_ERROR = f'{CONFIG_FILE_NAME}: "{key}" must be a number'
            continue
        ns[name] = val


def configHosts():
    hosts = CONFIG.get("hosts", {})
    return hosts if isinstance(hosts, dict) else {}


def desktopSessionsDir():
    d = CONFIG.get("desktopSessionsDir")
    return os.path.expanduser(d) if isinstance(d, str) else \
        os.path.join(os.path.expanduser("~"), ".config", "Claude", "claude-code-sessions")
