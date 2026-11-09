# z-agent-guard

Permission guard for Claude Code Bash calls: remembers approvals for `sudo`, `rm`,
containers, scripts and ssh as hand-editable rules, and adds git authorization
keywords and per-session grants typed into prompts.

Docs: [docs/z-agent-guard.md](docs/z-agent-guard.md). Stdlib-only Python 3.

```bash
python3 -I -m unittest discover -s tests
```
