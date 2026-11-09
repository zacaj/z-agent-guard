"""z-agent-guard tests. Run: python3 -m unittest discover -s tests

Each test gets an empty temp config dir (ZAG_CONFIG) so the live rules are never
read or written.
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_tmpConfig = tempfile.mkdtemp(prefix="zag-test-config-")
os.environ["ZAG_CONFIG"] = _tmpConfig
sys.path.insert(0, ROOT)

from zag import grants, hook, rules, storage  # noqa: E402

ENTRY = os.path.join(ROOT, "z-agent-guard.py")


class GuardTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="zag-test-")
        storage.RULES_PATH = os.path.join(self.dir, "rules.json")
        storage.RULES_DIR = os.path.join(self.dir, "rules.d")
        storage.ARCHIVE_PATH = os.path.join(self.dir, "rules.archive.json")
        storage.MAINT_STAMP = os.path.join(self.dir, ".maintenance")
        storage.RECOVERY_PATH = os.path.join(self.dir, "rules.recovery.json")
        storage.DESKTOP_SESSIONS_DIR = os.path.join(self.dir, "desktop")
        with open(storage.MAINT_STAMP, "w"):
            pass  # no maintenance unless a test asks for it
        rules.currentEnv = lambda: "host"

    def writeRules(self, ruleList, **extra):
        storage.writeJson(storage.RULES_PATH, {"rules": ruleList, "pending": [], **extra})

    def decide(self, cmd, cwd="/", session="S"):
        return hook.decide(cmd, cwd, session, storage.loadRules())[0]

    def run_(self, fn, data):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            fn(data)
        text = out.getvalue().strip()
        return json.loads(text) if text else None

    def pre(self, cmd, tid="t1", **kw):
        d = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd},
             "session_id": "S", "cwd": "/", "tool_use_id": tid, **kw}
        out = self.run_(hook.handlePre, d)
        return out["hookSpecificOutput"]["permissionDecision"] if out else None


class TestRm(GuardTest):
    def test_tmp_dirs(self):
        self.assertEqual(self.decide("rm -rf /tmp/x"), "allow")
        self.assertEqual(self.decide("sudo rm -rf /var/tmp/a/tmp/b"), "allow")
        self.assertEqual(self.decide("rm -rf /var/tmp/x/*"), "allow")

    def test_tmp_dir_itself_or_glob_in_it(self):
        self.assertEqual(self.decide("rm -rf /var/tmp"), "ask")
        self.assertEqual(self.decide("rm -rf /tmp/*"), "ask")

    def test_dotdot_and_trailing_slash_symlink(self):
        self.assertEqual(self.decide("rm -rf /var/tmp/a/../../etc"), "ask")
        link = os.path.join(self.dir, "tmp", "link")
        os.makedirs(os.path.dirname(link))
        os.symlink("/etc", link)
        self.assertEqual(self.decide(f"rm -rf {link}"), "allow")
        self.assertEqual(self.decide(f"rm -rf {link}/"), "ask")

    def test_outside_tmp_asks(self):
        self.assertEqual(self.decide("rm -rf /opt/x"), "ask")

    def test_deny_with_placeholders(self):
        self.writeRules([{"decision": "deny", "kind": "cmd", "sudo": True, "session": "*", "path": "/",
                          "env": "*", "match": r"re:(sudo )?rm( -\S+)* ({home}/?|{project}/?\*?)"}])
        self.assertEqual(self.decide("rm -rf ~"), "deny")
        proj = os.path.join(self.dir, "p")
        os.makedirs(os.path.join(proj, ".git"))
        self.assertEqual(self.decide("rm -rf .", cwd=proj), "deny")
        self.assertEqual(self.decide("rm -rf ./build", cwd=proj), "allow")  # project is under /tmp
        self.assertEqual(self.decide("rm -rf .", cwd="/opt/proj"), "deny")  # no repo: project = cwd
        self.assertEqual(self.decide("rm -rf ./build", cwd="/opt/proj"), "ask")


class TestSudo(GuardTest):
    def test_read_only(self):
        self.assertEqual(self.decide("sudo cat /etc/shadow"), "allow")
        self.assertEqual(self.decide("sudo find /var -name x"), "allow")
        self.assertEqual(self.decide("sudo /usr/bin/ls /root"), "allow")

    def test_write_args(self):
        for cmd in ("sudo sort -o /etc/x y", "sudo xxd a b", "sudo dmesg -C", "sudo find / -delete"):
            self.assertEqual(self.decide(cmd), "ask", cmd)

    def test_substitutions(self):
        self.assertEqual(self.decide('sudo cat "/x/$(sudo ls /x | head -1)"'), "allow")
        self.assertEqual(self.decide('sudo cat "$(sudo rm -rf /opt/x)"'), "ask")

    def test_wrappers_and_bin_path(self):
        self.writeRules([{"decision": "allow", "kind": "cmd", "match": "sudo chroot /var/tmp/* *$",
                          "session": "*", "path": "/", "env": "*"}])
        self.assertEqual(self.decide("sudo timeout 120 /usr/bin/chroot /var/tmp/r env A=1 x"), "allow")

    def test_sudo_rule_needs_sudo_true(self):
        self.writeRules([{"decision": "allow", "kind": "pkill", "match": "foo", "session": "*", "path": "/"}])
        self.assertEqual(self.decide("sudo pkill foo"), "ask")


class TestRules(GuardTest):
    def test_specificity_and_deny(self):
        self.writeRules([
            {"decision": "ask", "kind": "cmd", "match": "sudo foo", "session": "*", "path": "/"},
            {"decision": "allow", "kind": "cmd", "match": "sudo foo", "session": "S", "path": "/"},
        ])
        self.assertEqual(self.decide("sudo foo"), "allow")
        self.assertEqual(self.decide("sudo foo", session="other"), "ask")
        data = storage.loadRules()
        data["rules"].append({"decision": "deny", "kind": "cmd", "match": "sudo **", "session": "*", "path": "/"})
        storage.writeJson(storage.RULES_PATH, data)
        self.assertEqual(self.decide("sudo foo"), "deny")

    def test_glob_semantics(self):
        self.assertTrue(rules.textMatches("a * c", "a b c"))
        self.assertFalse(rules.textMatches("a * c", "a b b c"))
        self.assertTrue(rules.textMatches("a *$", "a b c d"))
        self.assertTrue(rules.textMatches("a ** d", "a b c d"))


class TestLearning(GuardTest):
    def test_approval_is_learned_and_counted(self):
        self.assertEqual(self.pre("sudo rm -rf /opt/x"), "ask")
        self.run_(hook.handlePost, {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "t1",
                                    "session_id": "S", "cwd": "/", "tool_input": {"command": "x"}})
        self.assertEqual([r["match"] for r in storage.loadRules()["rules"]], ["sudo rm -rf /opt/x"])
        self.assertEqual(self.pre("sudo rm -rf /opt/x", tid="t2"), "allow")
        self.assertEqual(storage.loadRules()["rules"][0]["uses"], 1)

    def test_bypass_mode_never_asks(self):
        self.assertIsNone(self.pre("sudo rm -rf /opt/x", permission_mode="bypassPermissions"))

    def test_broken_rules_file_asks_and_is_kept(self):
        with open(storage.RULES_PATH, "w") as f:
            f.write("{broken")
        self.assertEqual(self.pre("ls"), "ask")  # unusable file: ask about everything
        self.assertEqual(self.pre("sudo rm -rf /opt/x"), "ask")
        with open(storage.RULES_PATH) as f:
            self.assertEqual(f.read(), "{broken")


class TestGit(GuardTest):
    def test_keywords(self):
        self.assertEqual(grants.gitAuthFrom("ok lets Commit that"), {"commit"})
        self.assertEqual(grants.gitAuthFrom("Commit that"), set())
        self.assertEqual(grants.gitAuthFrom(grants.stripInjected("ok `Commit*` it")), set())

    def test_decisions(self):
        d = lambda cmd, auth: hook.decide(cmd, "/", "S", storage.emptyRules(), auth)[0]  # noqa: E731
        self.assertEqual(d("git add -A && git commit -m x", {"commit"}), "allow")
        self.assertEqual(d("git commit -m x", set()), "ask")
        self.assertEqual(d("git push -f origin main", {"push"}), "ask")
        self.assertEqual(d("git status && git stash", {"stash"}), "allow")


class TestPromptGrants(GuardTest):
    def prompt(self, text):
        return self.run_(grants.handlePrompt, {"prompt": text, "session_id": "S"})

    def test_markers_only_prompt_is_blocked_and_recorded(self):
        out = self.prompt("Commit* [docker run*$]*")
        self.assertEqual(out["decision"], "block")
        g = storage.loadRules()["grants"]["S"]
        self.assertEqual((g["git"], g["cmds"]), (["commit"], ["docker run*$"]))
        self.assertEqual(self.decide("docker run --rm alpine ls"), "allow")
        self.prompt("[docker run*$]-* Commit-*")
        self.assertNotIn("S", storage.loadRules().get("grants", {}))

    def test_sentence_start_keyword_blocks(self):
        self.assertEqual(self.prompt("Push that please")["decision"], "block")
        self.assertIsNone(self.prompt("hello there"))

    def test_code_spans_ignored(self):
        self.assertIsNone(self.prompt("eg `[a]* Commit*`"))


class TestStorage(GuardTest):
    def old(self, match, **kw):
        return {"decision": "allow", "kind": "cmd", "match": match, "session": "S", "path": "/p",
                "env": "host", "at": "2020-01-01 00:00:00", **kw}

    def test_archive_and_revive(self):
        self.writeRules([self.old("sudo a"), self.old("sudo b *$")])
        os.remove(storage.MAINT_STAMP)
        with storage.Lock():
            storage.saveRules(storage.loadRules())
        self.assertEqual([r["match"] for r in storage.loadArchive()], ["sudo a"])
        d = hook.decide("sudo a", "/p", "S", storage.loadRules())[0]
        self.assertEqual(d, "allow")
        storage.reviveRules(list(rules.REVIVED))
        self.assertEqual(storage.loadArchive(), [])
        self.assertIn("sudo a", [r["match"] for r in storage.loadRules()["rules"]])

    def test_folder_files_and_superseded(self):
        many = [self.old(f"sudo x{i}", at=time.strftime("%Y-%m-%d %H:%M:%S")) for i in range(storage.SPLIT_MIN)]
        many.append(self.old("sudo x*", at=time.strftime("%Y-%m-%d %H:%M:%S")))
        self.writeRules(many)
        os.remove(storage.MAINT_STAMP)
        with storage.Lock():
            storage.saveRules(storage.loadRules())
        self.assertEqual(len(storage.folderFiles()), 1)
        with open(storage.RULES_PATH) as f:
            self.assertEqual(json.load(f)["rules"], [])
        loaded = storage.loadRules()["rules"]
        self.assertEqual(len(loaded), storage.SPLIT_MIN + 1)
        self.assertEqual(sum(1 for r in loaded if r.get("supersededBy") == "sudo x*"), storage.SPLIT_MIN)


class TestConfig(unittest.TestCase):
    def guard(self, cfg, cmd):
        d = tempfile.mkdtemp(prefix="zag-cfg-")
        with open(os.path.join(d, "config.json"), "w") as f:
            f.write(cfg)
        out = subprocess.run([sys.executable, "-I", ENTRY, "--test", cmd], capture_output=True, text=True,
                             env={**os.environ, "ZAG_CONFIG": d}).stdout
        return out.split(" |")[0]

    def test_extend_read_only_sudo(self):
        self.assertEqual(self.guard('{"readOnlySudo": ["gdb"]}', "sudo gdb -p 1"), "allow")
        self.assertEqual(self.guard("{}", "sudo gdb -p 1"), "ask")

    def test_bad_config_asks(self):
        self.assertEqual(self.guard('{"readOnlySudo": "gdb"}', "sudo ls"), "ask")


if __name__ == "__main__":
    unittest.main()
