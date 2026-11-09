"""z-agent-guard: util (moved verbatim from the single-file hook)."""
import hashlib
import os
import time


def sha(data):
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()[:20]


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


def short(s, n=60):
    return s if len(s) <= n else s[:n - 1] + "…"
