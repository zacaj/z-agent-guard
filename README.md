# z-agent-guard

A permission guard for Claude Code's Bash tool. It runs as a hook, understands the
commands it's asked about (compound commands, `sudo`, wrappers, ssh, containers, script
files, git), remembers your approvals as hand-editable rules, and lets you grant things
from your prompt instead of clicking through prompts.

Stdlib-only Python 3. Full reference: [docs/z-agent-guard.md](docs/z-agent-guard.md).

## Why: what the built-in permissions can't do

Claude Code's `allow`/`ask`/`deny` rules are prefix/glob matches on command text. That
breaks down quickly:

| Situation | Built-in rules | z-agent-guard |
|---|---|---|
| `rm -rf /tmp/build-x` vs `rm -rf /etc` | One `rm` pattern covers both, or you're prompted for every scratch cleanup. `Bash(rm -rf /*)` in `deny` blocks *every* absolute path. | `rm` of anything inside a `tmp` dir is allowed (symlinks and `..` resolved; `rm -rf link/` judged by its target). `/`, `~`, `/etc`, the project root… are denied. Everything else asks once and is remembered per path. |
| `sudo cat /var/log/x`, `sudo dmesg` | `sudo *` is all or nothing. | A read-only sudo list (`cat`, `ls`, `find`, `journalctl`, …) is allowed, with write-capable arguments still asking (`find -delete`, `sort -o`, `dmesg -C`). |
| `python3 x.py`, `./build.sh`, `sudo bash fix.sh` | A rule allows the *filename*, whatever the file contains next time. | Script rules are keyed by path **and content hash**: approved once, re-asked when the script changes. Inline/heredoc scripts are hashed too. |
| `sudo timeout 120 /usr/bin/chroot /var/tmp/r …` | Doesn't match a `sudo chroot …` rule. | Wrappers (`timeout`, `nice`, `env`, `setsid`, …) and `/usr/bin/` paths are normalized before matching. |
| `docker run --rm -e X=1 -p 80:80 img` | Every new env var or port is a new prompt; a `docker run *` rule also allows `--privileged -v /:/host`. | Container rules keep only what matters for safety (privileges, mounts, devices, caps, user, image, command) and match piece by piece. |
| `ssh nas 'docker ps; sudo systemctl restart x'` | `ssh *` approves anything on any host. | The remote command is parsed like a local one and rules are scoped to that host, which is recognized across IPs, tailscale names and ssh aliases (via `ssh -G` and known_hosts). |
| Compound commands: `cd x && make && sudo make install` | Each subcommand needs its own rule; one prompt approves all of it. | Split into parts; only unknown parts ask, and the prompt says which part and how it differs from the closest approved rule. |
| "Commit that" / "push it" | `git commit`/`git push` are always allowed or always prompt. | Typing **Commit**, **Push**, **Rebase**… capitalized mid-sentence authorizes that git operation for the turn; force pushes, `branch -D`, `stash drop`… still ask. |
| "Let it run docker for the rest of this session" | Only "always allow" (permanent) or per-call. | Session grants from the prompt: a prompt containing just `[docker run*$]*` or `Commit*` is recorded and never shown to the agent. `-*` revokes. |
| Same command fine in one project/container/host, not another | Rules are global (or per settings file). | Every rule can be scoped by session, project folder (or parent), and environment (`host`, a container, an ssh host). Most specific rule wins; `deny` always wins. |
| Skip-permissions sessions | Hooks still prompt. | The guard stays silent in `bypassPermissions` mode, except for `deny`. |

## Features

- **Learns from approvals.** When it asks and you approve, the rule it proposed is saved
  (scoped to the session and project). Edit the pending entry before approving to widen
  it (`*`, `**`, `*$`, `re:`, `{project}`, `{home}`) or flip it to `ask`/`deny`.
- **Readable rules.** Pretty-printed JSON with `lastUsed`/`uses` counters; folders with
  many rules get their own file; stale rules move to an archive (and come back if used);
  rules made redundant by a broader one are marked `supersededBy` for cleanup.
- **Fails safe.** A broken rules or config file makes every call ask (and is never
  overwritten); approvals made meanwhile are kept in a recovery file and merged later.
  Any internal error also means "ask".
- **Per-machine config.** Code and data are separate: install the code once, keep a
  `configs/<hostname>/` per machine (config.json + rules). Works when `~/.claude` is
  bind-mounted into a devcontainer.

## Examples

Rules (in `configs/<name>/rules.json`):

```json
{ "decision": "allow", "kind": "cmd", "match": "sudo chroot /var/tmp/jjp_run *$", "session": "*", "path": "/" }
{ "decision": "allow", "kind": "cmd", "match": "rm -rf {project}/build", "session": "*", "path": "/" }
{ "decision": "allow", "kind": "script", "match": "/home/me/src/app/scripts/*", "sha": "*", "session": "*", "path": "/home/me/src/app" }
{ "decision": "deny",  "kind": "cmd", "match": "sudo find ** -delete**", "session": "*", "path": "/", "env": "*" }
```

Prompts:

```
ok, Commit that and Push           -> git add/commit and a plain push allowed this turn
Commit* Rebase*                    -> (prompt not sent) both allowed for the session
[podman run *$]*                   -> (prompt not sent) any podman run allowed for the session
Rebase-*                           -> (prompt not sent) revoked
```

Checking a command:

```bash
python3 ~/.claude/z-agent-guard/app/z-agent-guard.py --test 'sudo rm -rf /var/tmp/x && git push -f'
```

## Install

```bash
mkdir -p ~/.claude/z-agent-guard/configs
git clone ssh://git@git.zacaj.com:222/zacaj/z-agent-guard.git ~/.claude/z-agent-guard/app
cp -r ~/.claude/z-agent-guard/app/examples/config ~/.claude/z-agent-guard/configs/"$(hostname)"
```

Then merge [examples/settings-hooks.json](examples/settings-hooks.json) into the `hooks`
section of `~/.claude/settings.json`, and remove broad `sudo`/`rm`/`git`/`ssh`/`docker`
entries from its `permissions.ask` list (an `ask` there overrides the hook's `allow`).
Changes apply to running sessions.

The starter config ([examples/config](examples/config)) has no machine-specific rules, only
`deny` rules for the obvious disasters:

- `rm` of `/`, base system folders (`/etc`, `/usr`, `/var`, …), `~`, `~/src` or the project root
- `rm --no-preserve-root`
- `sudo find … -exec/-delete/-fprint`
- `sudo mkfs*`, `wipefs`, `fdisk`, `parted`, … and `sudo dd … of=/dev/…`
- `sudo chmod/chown/chgrp -R` on a base folder or `~`

Everything else starts out as "ask once, then remember". Add ssh host aliases or extra
read-only sudo commands in `config.json`. Details, config reference and migration from
the old single-file hook: [docs/z-agent-guard.md](docs/z-agent-guard.md).

## Development

Develop in a separate checkout and `git pull` into `app/` to deploy, so unfinished edits
never run live.

```bash
python3 -I -m unittest discover -s tests          # unit tests (temp config dirs)
tools/replay.py --guard . --rules snap.json > new.jsonl   # replay every Bash call in your transcripts
tools/compare.py old.jsonl new.jsonl              # diff two versions' decisions
```
