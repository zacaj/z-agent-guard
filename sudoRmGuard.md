# sudoRmGuard

A Claude Code hook that decides Bash calls involving `sudo`, `rm`, `docker`/`podman` and script runs. It asks you the first time it sees one of these. After you approve, it remembers that in `sudoRmGuard-rules.json`, which you can edit by hand.

| File | Purpose |
|---|---|
| `sudoRmGuard.py` | the hook |
| `sudoRmGuard-rules.json` | saved rules and pending asks (edit freely) |
| `sudoRmGuard-rules.json.lock` | lock file used while writing; ignore it |
| `sudoRmGuard-rules.recovery.json` | only exists while the rules file is broken (see below) |

The hook is registered in `~/.claude/settings.json` for `PreToolUse`, `PostToolUse` and `PostToolUseFailure`, all with matcher `Bash`. Settings changes take effect in running sessions.

## How a call is decided

The command is split into parts at `;`, `&&`, `||`, `|`, `&` and newlines. Each part falls into one of three groups:

| Group | Examples | What happens |
|---|---|---|
| **ok** | `echo`, `cd`, `ls`, `cat`, `grep`, `head`, `sleep`…; read-only `sudo` (`ls`, `cat`, `grep`, `tail`, `dmesg`, `journalctl`, `strings`, `objdump`, `pgrep`, `dmidecode`…); `rm`/`sudo rm` of paths strictly inside any directory named `tmp` (`/tmp/x`, `/var/tmp/x`, `/var/tmp/chroot/tmp/x`, `~/src/p/tmp/x`; symlinks resolved, `link/` judged by its target; `rm /var/tmp/*` itself is not inside); `docker`/`podman` `ps`, `logs`, `inspect`, `images`, `compose ps`/`logs`… | fine |
| **guarded** | other `sudo`; `rm` outside a tmp dir; running a script file; `docker`/`podman` `run`, `rm`, `rmi`, `prune`, `push`… | needs a rule |
| **deferred** | anything else | left to your settings rules and the auto-mode classifier |

The hook's answer for the whole call:
- **ask** if any guarded part has no matching `allow` rule, or matches an `ask` rule. The proposed rules are added to `pending`.
- **allow** if every guarded part is allowed and every other part is ok.
- **no decision** if the guarded parts are allowed but some other part is deferred. A hook `allow` would approve the whole call, so the hook stays out of it.
- **ask** if the hook can't understand the command, or hits an error. A parse bug should only ever cost you an extra prompt.

What the hook can't do:
- Override `deny` rules in settings.
- Answer `allow` when a settings `ask` rule matches. The `ask` rule wins.
- Add a "don't ask again" option to the prompt. Remembering approvals is handled by this rules file instead.

**Skip-permissions sessions** (`permission_mode: bypassPermissions`): the hook never
returns `ask` (a hook ask would still prompt there), and nothing is added to `pending`.
`deny` rules still block. With a broken rules file the hook stays silent in this mode.

## Learning from approvals

1. When the hook asks, it writes a `pending` entry: the call id, the command, and the rules it proposes.
2. If the call then runs, a `PostToolUse` or `PostToolUseFailure` hook fires, which means you approved it. The entry's rules move into `rules`, including any edits you made while it was pending.
3. A call you deny never runs, so nothing is learned. Its pending entry expires after **2 hours**, and the list is capped at **50** entries.
4. If the same command asks again while it's still pending, the existing entry and any edits you made to it are kept.

When a script rule is learned, the hook hashes the file *after* the command runs. If the approved command edited the script before running it, you saw that edit in the command, so the rule covers the edited version.

If the command has several commands, several lines or heredocs, the reason starts with a note like `[3 commands, 5 lines, 1 heredoc; asking about:]`. That way, the guarded part isn't the only thing you notice in a long command.

The prompt explains what's new by comparing against your closest approved literal rule (wildcard and `re:` rules aren't compared). It uses the same session/path scope that matching uses:
- **container:** the image change, flags or mounts added and dropped, and the command change, e.g. `vs rule from 2026-10-31 19:00: new -v /dev/bus/usb:/dev/bus/usb; dropped -v /dev/dri:/dev/dri`
- **script:** `never approved`, or `content changed since approved <date>`
- **cmd / pkill:** `closest approved: '<rule>'`, if one starts with the same two words

## The rules file

```json
{
  "rules": [
    {
      "decision": "allow",
      "kind": "cmd",
      "match": "sudo chroot /var/tmp/jjp_run *",
      "session": "*",
      "path": "/var/home/zacaj/src/pinball-asset-decryptor",
      "at": "2026-10-31 18:33:49"
    }
  ],
  "pending": [ ... ]
}
```

The hook rewrites the file in this layout: indented, fields in a fixed order, both lists sorted by `at`. The hook treats the file as **unusable** if:
- it isn't valid JSON or can't be read,
- `rules` or `pending` isn't a list,
- a rule has no string `kind` or `match`,
- a rule's `decision` isn't `allow` or `ask`,
- a `re:` pattern doesn't compile.

While the file is unusable:
- **Every Bash call asks**, even `echo`. The reason starts with `⚠ sudoRmGuard-rules.json is unusable (<error, with line/column>)`.
- The hook **never writes** to the broken file. New pending entries and approvals go to `sudoRmGuard-rules.recovery.json`.
- The first time a hook run finds the file usable again, it merges the recovery data in and deletes the recovery file. Pending entries are added, and approvals given in the meantime become rules. It doesn't matter whether you fixed the file before or after answering the prompt. A denied prompt stays pending, as usual.

If the hook itself crashes before a command runs, it answers `ask` with the error, rather than letting the call fall through to the other rules.

### Fields

| Field | Values | Meaning |
|---|---|---|
| `decision` | `allow` / `ask` / `deny` | `ask` means always prompt for this. Approving the prompt does *not* turn it into `allow`. Use it for things you'll usually say yes to but still want to see each time. `deny` blocks the command outright, without a prompt; the agent is told why. |
| `kind` | `cmd`, `script`, `inline`, `pkill`, `container` | What `match` describes (see below). A rule only applies to parts of the same kind. |
| `match` | text with `*` / `*$` wildcards, or `re:<regex>` | See [Matching](#matching). |
| `session` | session id or `"*"` | `"*"` means every session. |
| `path` | a directory or `"/"` | Applies when the session's project folder (the nearest folder containing `.git`, otherwise the cwd) is this directory or inside it. `"/"` means everywhere. |
| `env` | `host`, `container:<name>`, `ssh:[user@]host[:port]`, wildcards, or `"*"` | Where the command runs. Learned rules record it. `container:<name>` comes from podman's `/run/.containerenv`, or the hostname under docker (`/.dockerenv`). `ssh:…` is for commands run over ssh (see [SSH](#ssh)). `*` wildcards work as in `match`. A **missing** `env` means any local env (host or container) but **never** an ssh host. `"*"` means everywhere, including ssh. Your devcontainer sessions share this file, so use this to keep container-only approvals off the host. |
| `from` | text | Informational only: where the rule was first learned (env, project, session). Not used for matching, so it still tells you where a widened rule came from. |
| `sha` | 20 hex chars or `"*"` | **script rules only.** A short hash of the file's content. `"*"` accepts any content. |
| `sudo` | `true` / `false` | **script, inline, pkill.** `true` covers the command with or without sudo. `false`, or a missing field, covers only the non-sudo form, so approving `python3 x.py` never approves `sudo python3 x.py`. |
| `preview` | text | **inline rules only.** The start of the script, for your reference. Not used for matching. |
| `at` | `YYYY-MM-DD HH:MM:SS` | When the rule was learned, in local time. Used for sorting and cleanup. |
| `lastUsed` / `uses` | timestamp / count | Added by the hook the first time the rule decides a later call, whether it allowed, asked or denied, and updated on each use after that. A brand-new rule has neither, so a rule without them has never been used since it was learned. Duplicate parts within one call count once. Safe to edit or delete. |

### Kinds

| `kind` | Created for | `match` contains | Default scope when learned (plus the current `env`) |
|---|---|---|---|
| `cmd` | other `sudo`, `rm` outside a tmp dir, destructive docker commands, unparseable commands | the cleaned-up part (see below) | this session and project |
| `script` | `python3 x.py`, `bash x.sh`, `node x.js`, `./x.sh`, `sudo python3 x.py`… | the script's absolute path, with `sha` set | this session and project |
| `inline` | `sudo python3 -c '…'`, `sudo bash -c '…'`, `sudo python3 - <<EOF` | a hash of the script text | this session and project |
| `pkill` | `sudo pkill [-SIG] [-x] NAME`, `sudo killall NAME` | `NAME`, or `-f PATTERN` for `pkill -f`. Any signal matches. | this session and project |
| `container` | `[sudo] docker`/`podman` `run`/`create` | `[sudo] tool run <security flags> IMAGE [command]` | this session and project |

Syntax checks don't count as running a script: `node --check`/`-c`, `bash`/`sh -n`, `perl -c`, `ruby -c`. Neither do `python3 -m …` and `--version`/`--help`. Without sudo these go to your normal rules and the classifier; under sudo they get a `cmd` rule. Inline-code flags depend on the interpreter: `python -c`, `node -e`/`-p`, `perl -e`/`-E`, `ruby -e`, and `-c` for shells.

Inline scripts are only guarded under `sudo`. A plain `python3 -c` or heredoc goes to the classifier as usual.

**How `match` text is cleaned up**, for `cmd` and `container` rules:
- `2>&1`, `>/dev/null`, `2>/dev/null` and `&>/dev/null` are removed.
- Known variables (`S=…; rm $S/x`) and `~` are expanded.
- Wrappers that only change how a command runs are removed along with their options, both before and after `sudo`: `timeout` (with its duration), `nice`, `ionice`, `stdbuf`, `nohup`, `setsid`, `time`, `command` and `env`. `sudo timeout 30 chroot …` and `sudo timeout -k 5 90s chroot …` both become `sudo chroot …`, so a changing timeout doesn't break the rule. `sudo env VAR=x …` assignments are removed too. Assignments written directly after sudo (`sudo VAR=x cmd`) are kept.
- A command given by full path in a system bin dir (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin`) is shortened to its name: `sudo /usr/bin/chroot …` → `sudo chroot …`. Other paths (`/opt/x/chroot`) are kept.
- `rm` paths are made absolute, taking any earlier `cd` in the same command into account.
- An `rm` with several paths becomes one rule per path, with the same flags on each. Paths inside a tmp dir get no rule (with or without `sudo`). For example, `rm -f a b` gives `rm -f /abs/a` and `rm -f /abs/b`, and each one can be allowed or widened on its own.
- Extra whitespace is collapsed.

So `sudo chroot /var/tmp/jjp_run /usr/sbin/hasplmd_x86_64 -h 2>&1 | head -40` is stored as `sudo chroot /var/tmp/jjp_run /usr/sbin/hasplmd_x86_64 -h`. The `| head -40` part is ok on its own and gets no rule.

**Container rules** keep the options that affect what a container can reach. They drop the rest.

| Kept | Dropped |
|---|---|
| `--privileged`, `-v`/`--volume`, `--mount`, `--device`, `--cap-add`, `--security-opt`, `-u`/`--user`, `--entrypoint`, `--pid`/`--ipc`/`--userns`/`--uts`/`--cgroupns`, `--group-add`, `--network host`, unknown flags, the image, the command after the image | `--rm`, `-d`, `-i`, `-t`, `--name`, `-e`/`--env*`, `-p`, `-w`, `--hostname`, `--mac-address`, `--restart`, resource limits, other `--network` values… |

Kept flags are sorted, so the rule doesn't depend on the order you wrote them in. Example:

```
sudo podman run --privileged --security-opt=label=disable -v /var/tmp/jjp_run:/jail ubuntu:24.04 bash /probe/x.sh
```

## Matching

For `cmd`, `pkill` and `script` rules, `match` is compared against the whole of one cleaned-up part. A pattern can only ever cover a single part, never the next command after a `;`. `container` rules are matched piece by piece (see below).

| Pattern | Meaning |
|---|---|
| plain text | exact match |
| `*` | any run of **non-whitespace** characters, including none. It stays inside one word, path or flag value. `/` is fine, so `/a/*` matches `/a/b/c`. |
| `**` | any text **including spaces**, anywhere in the pattern. ` ** ` between two spaces can also match nothing, so `a ** b` matches `a b`. |
| `*$` at the very end | same as a trailing `**` |
| `re:<regex>` | Python regex that has to match the whole part (or the whole container key) |

Everything else is literal: `?` and `[...]` have no special meaning. Use `**` sparingly in `allow` rules, because it can swallow extra arguments such as another `-v` mount or a `-exec`. It's mainly for `deny` and `ask` rules that look for something anywhere in a command.

### Placeholders

`{project}` (the call's project: git root above cwd, else cwd) and `{home}` are replaced
before matching, in plain and `re:` patterns. The built-in deny rule uses it:
`re:(sudo )?rm( -\S+)* (/(home|var|usr|etc|…)?/?\*?|{project}/?\*?)` denies `rm` of `/`,
base system/home folders (`/etc`, `/var/home/zacaj`, `/var/tmp`, …, and their `/*`) and the
project root itself; files inside them still just ask. Example allow for build output in
any project: `{"decision": "allow", "kind": "cmd", "match": "rm -rf {project}/build", "path": "/", "session": "*"}`.

### Container rules

A container `match` is split into pieces: the leading `[sudo] tool run`, each kept flag (`--privileged`, `--cap-add=X`, `-v SRC:DST`, `-u USER`), the image, and the command after it. A command matches when:
- the leading `[sudo] tool run` is the same,
- **every** flag or mount in the command matches **one** of the rule's flag patterns (the order doesn't matter, and a rule pattern can match several mounts),
- the image matches the rule's image pattern,
- the command matches the rule's command pattern. No command in the rule means the run must have no command either.

A rule may list flags the command doesn't use, since less privilege is fine. But every flag the command does use has to be covered, so a rule without `--privileged` never approves a privileged run.

### Examples

| `match` | Allows |
|---|---|
| `sudo chroot /var/tmp/jjp_run *$` | anything run inside that chroot |
| `sudo chroot /var/tmp/jjp_run *` | any single program in that chroot, with **no** arguments |
| `sudo chroot /var/tmp/* *$` | anything in any chroot directly under `/var/tmp`, or deeper |
| `sudo rm -f /var/tmp/jjp_run/tmp/*` | deleting one path under that folder, with exactly `-f` |
| `sudo rm * /var/tmp/jjp_run/tmp/*` | the same with any single flag word (`-f`, `-rf`…) |
| `rm -rf /var/home/zacaj/src/*/node_modules` | `node_modules` in any project. Also set `path` to `/var/home/zacaj/src` or `/`. |
| `docker run nginx*` | image `nginx` / `nginx:tag`, no extra flags, no command |
| `docker run nginx* *$` | the same with any command |
| `sudo podman run --privileged --security-opt=label=disable -v /var/tmp/jjp_run/* -v /dev/dri:/dev/dri ubuntu:24.04 *$` | privileged `ubuntu:24.04` runs with any number of mounts from under `/var/tmp/jjp_run/` plus `/dev/dri`, and any command. `-v /etc:/x` or `--cap-add` would still ask. |
| `aksusbd_*` | on a `pkill` rule: any process whose name starts with `aksusbd_` |
| `re:(aksusbd\|hasplmd)_x86_64` | on a `pkill` rule: either of the two processes |
| `re:sudo mount /dev/sd[a-z]\d+ /mnt` | on a `cmd` rule: mounting any `sdXN` partition at `/mnt` |
| `/var/home/zacaj/src/speakereq/*` | on a `script` rule with `"sha": "*"`: any script under that folder, any content |

Things to keep in mind:
- `*$` matches `bash -c '…'` and anything else. `sudo chroot /var/tmp/jjp_run *$` really does mean "anything as root inside that chroot".
- `-v /var/tmp/jjp_run/*` doesn't cover `-v /var/tmp/jjp_run:/jail`, which mounts `jjp_run` itself, because there's no `/` after it. Add that mount as its own pattern. `jjp_run*` would cover both, but also `jjp_run2`.
- Arguments that contain spaces are quoted in `match` (`'a b'`), so a plain `*` can't match them. Use `*$` or `re:`.
- When several rules match, the **most specific** one decides (see [Rule precedence](#rule-precedence)).
- In `re:` rules, regex characters like `.`, `+` and `(` are special. Escape them to match them literally.

## Rule precedence

When several rules match a part, the most specific one decides. Specificity is compared field by field, in this order. The first difference decides:

1. **`session`:** a specific session id beats `*` or a missing session.
2. **`path`:** a deeper folder beats a shallower one. `/` or a missing path is least specific.
3. **`env`:** an exact env (`host`, `container:dev1`, `ssh:nas`) beats a wildcard (`container:*`, `ssh:*`), which beats `*` or a missing env.
4. **`match`:** literal text beats a pattern with `*`, which beats `*$` and `re:`. Within the same group, more literal characters win.

If an `allow` and an `ask` rule are equally specific, **`ask` wins**.

**`deny` always wins.** If any `deny` rule matches, the command is blocked, however specific the matching `allow` or `ask` rules are. That way a narrow `allow` can't override a safety deny.

Examples:
- a global `ask` plus an `allow` for one session → allowed in that session, asked everywhere else
- an `ask` for a path plus an `allow` for one session → allowed in that session, because session is compared first
- in one scope, `allow sudo rm *$` plus `ask sudo rm -rf /var/tmp/important` → that one path asks, everything else is allowed
- `allow sudo find /var/tmp/*$` plus a global `deny sudo find ** -exec**` (and `deny sudo find ** -delete**`) → read-only finds under `/var/tmp` are allowed, and any `-exec`/`-execdir`/`-delete` is blocked

## SSH

`ssh [options] [user@]host '<cmd>'` isn't judged as one command. The remote `<cmd>` is split and judged exactly like a local command, and every part gets `env: "ssh:[user@]host[:port]"`. So `ssh nas 'docker ps; ls ~/x'` is allowed, and `ssh linveo 'sudo systemctl restart nginx'` asks once and is then remembered for that host only. Wrappers like `timeout 20 ssh …` are removed as usual.

- **Heredoc scripts:** `ssh host <<EOF` and `ssh host sh -s <<EOF` / `bash -s` treat the heredoc as the remote script.
- **Remote differences:**
  - `~` is kept as written, not expanded to your local home.
  - `rm` inside `/tmp` or `~/tmp` is checked as text only.
  - A remote script run (`ssh host 'python3 x.py'`) gets an exact-command `cmd` rule, because the file can't be hashed.
- **Always ask, as a whole (`env` = local):**
  - an interactive `ssh host` (no command, no heredoc)
  - forwarding or control options (`-L`, `-R`, `-D`, `-W`, `-w`, `-O`)
  - `-N`
  - `-o ProxyCommand`/`LocalCommand`/`RemoteCommand`/`KnownHostsCommand`, which run local commands
- **Same machine, different name:** an `ssh:X` rule also matches `ssh:Y` when the remote **user** is the same (as `ssh -G` resolves it) and any of these is true:
  1. X and Y are in the same `hosts` alias group (below),
  2. `ssh -G` resolves both to the same hostname and port (ssh config aliases),
  3. `known_hosts` has the same host key for both (via `ssh-keygen -F`, public keys only). This links tailscale and LAN addresses once you've ssh'd to each.
- **Wildcards:** `ssh:*` matches any host. A wildcard or `re:` in `env` is plain text matching, with no same-machine detection.

### Host aliases

For names that can't be linked automatically, add a top-level `hosts` section to the rules file. Each name maps to its aliases, and the hook keeps the section when it rewrites the file:

```json
"hosts": {
  "nas": ["192.168.2.15", "100.x.y.z", "Desktop-Win10"],
  "linveo": ["git.zacaj.com", "zacaj.com"]
}
```

This only takes effect once `Bash(ssh *)` is removed from the settings `ask` list. Otherwise that rule prompts for every ssh command no matter what the hook decides. Other remote tools like `scp`, `rsync` and `sftp` stay in `ask`.

## git authorization keywords

Some git subcommands are allowed only when your most recent typed message contains their
keyword, **capitalized and not at the start of a sentence** (start of message, or after
`.` `!` `?` or a newline). "ok lets Commit that" → yes; "Commit that", "lets commit that",
"I Committed it" → no, you get prompted.

| Keyword | Allows | Always asks anyway |
|---|---|---|
| Commit | `add`, `commit` | |
| Push | `push` | `-f`/`--force*`, `--delete`/`-d`, `--mirror`, `--prune`, `--all`, `--tags`, `+ref`, `:ref` |
| Branch | `branch`, `checkout`, `switch` | branch `-D`/`-d`/`-f`/`-M`/`-C`; checkout `-f`/`-B`/`--orphan`/`.`/`--` or an existing path; switch `-f`/`-C`/`--discard-changes`/`--orphan` |
| Stash | `stash` | `drop`, `clear` |
| Fetch | `fetch` | `--prune*`/`-p`/`-P`, `--force`/`-f`, `+ref` |
| Pull | `pull` | `--force`/`-f`, interactive rebase |
| Rebase | `rebase` | `-i`, `--exec`/`-x`, `--root` |
| Merge | `merge` | |
| Tag | `tag` | `-d`, `-f` |
| Remote | `remote` | `remove`/`rm`, `set-url`, `rename`, `prune` |

Read-only subcommands (`status`, `log`, `diff`, `show`, `blame`, `rev-parse`, `ls-files`,
`merge-base`, `describe`, …) never need a keyword and don't block approving a compound
command. Other git subcommands are left to settings. One message can carry several
keywords ("okay, Stash it and Rebase, then Push"); they last until your next message.

Only your own typed text counts: tool results, hook/system text and `<pasted_content>`
are ignored. Nothing is learned from these prompts. Settings `deny` rules still win.
Requires the matching `git …` entries to be removed from settings `ask` (an `ask` there
overrides the hook).

Test: `GIT_AUTH="commit push" python3 sudoRmGuard.py --test "git commit -m x && git push"`

### Session grants (`Keyword*`, `Keyword-*`, `[pattern]*`)

The same hook also runs on `UserPromptSubmit`:

| You type | Effect |
|---|---|
| `Keyword*` mid-sentence ("can you Commit* these separately?") | grants that keyword for the rest of the session; the agent gets a note that the marker isn't part of the request |
| `Keyword-*` mid-sentence | revokes it |
| a prompt that is **only** markers (`Commit* Rebase*`, `Push-*`, `[docker run*$]*`, `[npm publish]-*`) | recorded, then the prompt is **blocked** with a "✓ session grants now: …" message, so the agent never sees it |
| `[pattern]*` / `[pattern]-*` | (markers-only prompts) allow/stop allowing any command matching `pattern` (same syntax as `match`: `*`, `**`, `*$`, `re:`) for this session. Matched per simple command; `deny` rules still win; local only (not over ssh) |
| a keyword (any suffix) at the **start of a sentence** in a normal prompt | prompt is blocked with a reminder (could be ordinary capitalization); lowercase it or move it mid-sentence and resend |

Several markers can go in one prompt (`[cmd1]* [cmd2]-* Commit* Push-*`). Markers inside
`code` spans or ``` blocks never count (so you can quote the syntax). Prompts starting with `/` or `!` are ignored. Grants are stored per session in the rules
file's top-level `grants` (`{session: {"git": [...], "cmds": [...], "at": ...}}`, hand-editable)
and dropped after 14 days of no changes. A hook `allow` still can't override a settings `ask`. When you add a grant, the
confirmation/note warns (best guess, by comparing the text before the first wildcard) about
settings `ask` entries (user + project `settings*.json`) that would still prompt; for
`Keyword*` only broad entries like `git push*` are reported, not the force/delete ones.

## Automatic cleanup

Every time the hook writes the file, it removes:
- **Outdated script rules.** If several rules cover the same script path, `sudo` setting, `session`, `path` and `decision`, only the newest is kept. The older ones' `sha` can no longer match.
- **Rules for deleted scripts.** If a script rule's file no longer exists, the rule goes. Typical for `/tmp` scratch scripts.
- **Old pending entries:** older than 2 hours, or beyond the 50 most recent.

Rules with `"sha": "*"` or a wildcard or `re:` in `match` are never removed automatically.

## Changing the built-in lists

These are constants at the top of `sudoRmGuard.py`:

| Constant | Controls |
|---|---|
| `SCRATCH_ROOTS` | folders where `rm` is always ok (`/tmp`, `~/tmp`) |
| `SAFE_SUDO` / `SAFE_SUDO_BAD_ARGS` | read-only sudo commands, and the arguments that disqualify them (`dmesg -C`, `journalctl --vacuum…`) |
| `TRIVIAL` | commands that are ok alongside guarded parts |
| `CONTAINER_READONLY` / `COMPOSE_READONLY` / `CONTAINER_DESTRUCTIVE` | docker/podman subcommand groups |
| `RUN_KEEP_*` / `RUN_DROP_VALUE` / `RUN_BOOL_FLAGS` | which `run` flags go into a container rule |
| `PENDING_TTL` / `PENDING_MAX` | pending expiry and cap |

## Testing

```bash
python3 ~/.claude/hooks/sudoRmGuard.py --test 'sudo chroot /var/tmp/jjp_run /bin/sh -c id' /var/home/zacaj/src/pinball-asset-decryptor
```

This prints the decision and reason, plus any rules it would propose. It uses your current rules file with session id `test`, and writes nothing.

To find out what approved a past call, look in the session log (`~/.claude/projects/<project>/<session>.jsonl`). Each tool result has a `permissionDecision.source`: `hook`, `classifier`, `config`, `user_temporary`, and so on.
