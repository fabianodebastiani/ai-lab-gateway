"""Disposable Ubuntu first-run smoke: *actual* local root bootstrap + pairing.

Runs only inside a fresh GitHub-hosted Ubuntu 24.04 VM.
The real Gateway/Oracle/ChatGPT/Auth0/remote SSH are NOT contacted.
This is deliberately NOT a complete production code-to-ChatGPT E2E.
"""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
import threading
import unittest

from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_http import run_device_code_server

ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "scripts" / "ai_lab_prepare_linux_target.py"
CLIENT = ROOT / "scripts" / "device_code_pair_linux.py"
HOST_KEY = Path("/etc/ssh/ssh_host_ed25519_key.pub")
USER = "ai-gateway"
CODE = re.compile(r"^Código: ([A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4})$", re.M)
BANNED_GROUPS = {"sudo", "root", "wheel", "docker", "lxd", "adm"}


def invoke(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=timeout, check=False)


class FreshUbuntuRootRestrictedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise AssertionError("run tests as normal CI runner; use local sudo only for setup")
        os_name = Path("/etc/os-release").read_text()
        if 'ID=ubuntu' not in os_name:
            raise AssertionError("requires a fresh isolated Ubuntu runner")
        if not Path("/run/systemd/system").is_dir():
            raise AssertionError("requires real Ubuntu systemd, not a generic container")
        if invoke(["id", "-u", USER]).returncode == 0:
            raise AssertionError("test runner is not virgin: ai-gateway already exists")
        # This is the ONLY local bootstrap operation that alters the runner.
        # A disposable GitHub Ubuntu VM is discarded when the job finishes.
        prepare = invoke(["sudo", "-n", "--", "/usr/bin/python3", str(SETUP)], timeout=240)
        if prepare.returncode:
            raise AssertionError("local original-admin bootstrap failed; "
                                 + prepare.stderr[-800:] + prepare.stdout[-300:])
        if "AI_LAB_TARGET_PREPARED" not in prepare.stdout:
            raise AssertionError("bootstrap success marker missing")

    def test_real_ssh_service_and_nonroot_management_user(self):
        user = pwd.getpwnam(USER)
        self.assertNotEqual(user.pw_uid, 0)
        self.assertEqual(user.pw_dir, "/home/ai-gateway")
        self.assertEqual(user.pw_shell, "/bin/bash")
        groups = invoke(["id", "-nG", USER])
        self.assertEqual(groups.returncode, 0)
        self.assertFalse(set(groups.stdout.split()) & BANNED_GROUPS)
        self.assertTrue(HOST_KEY.is_file())
        self.assertTrue(invoke(["systemctl", "is-active", "ssh"]).stdout.strip() == "active")
        # Double-check target's management identity never gets general sudo.
        denied = invoke(["sudo", "-n", "-u", USER, "-H", "--",
                         "sudo", "-n", "/usr/bin/id", "-u"])
        self.assertNotEqual(denied.returncode, 0,
                            "Unexpected generic sudo granted to ai-gateway")

    def test_idempotent_setup_and_systemd_user_session(self):
        again = invoke(["sudo", "-n", "--", "/usr/bin/python3", str(SETUP)], timeout=240)
        self.assertEqual(again.returncode, 0, again.stderr[-800:])
        self.assertIn("AI_LAB_TARGET_PREPARED", again.stdout)
        self.assertEqual(invoke(["systemctl", "is-active",
                                 f"user@{pwd.getpwnam(USER).pw_uid}.service"]).stdout.strip(),
                         "active")
        linger = Path("/var/lib/systemd/linger") / USER
        self.assertTrue(linger.exists())

    def test_real_restricted_user_can_pair_once_with_loopback_lab_server(self):
        # Use an isolated localhost staging HTTP API and generated disposable
        # SSH identities. No trusted remote operator or root provisioner here.
        with tempfile.TemporaryDirectory(prefix="ai-lab-fresh-runner-") as temp:
            store = DeviceCodeStore(Path(temp) / "pairing.sqlite", hmac_key=b"Q" * 32)
            server = run_device_code_server(store)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}"
                # The runner's source checkout is inaccessible to the new
                # restricted user. Exercise the same root-local, owner/mode
                # constrained artifact installation as the actual bootstrap.
                cache = Path("/home/ai-gateway/.cache/ai-lab-gateway")
                prepared = invoke(["sudo", "-n", "--", "install", "-d", "-o", USER,
                                   "-g", USER, "-m", "0700", str(cache)])
                self.assertEqual(prepared.returncode, 0, prepared.stderr)
                target_client = cache / "device_code_pair_linux.py"
                staged = invoke(["sudo", "-n", "--", "install", "-o", USER,
                                 "-g", USER, "-m", "0600",
                                 str(CLIENT), str(target_client)])
                self.assertEqual(staged.returncode, 0, staged.stderr)
                client = invoke([
                    "sudo", "-n", "-u", USER, "-H", "--", "/usr/bin/python3",
                    str(target_client), "--base-url", url, "--no-wait",
                    "--name", "Disposable GitHub Ubuntu",
                    "--host-key", str(HOST_KEY),
                ], timeout=80)
                self.assertEqual(client.returncode, 0, client.stderr[-900:])
                self.assertIn("Aguardando autorização", client.stdout)
                self.assertIn("ainda não ativa", client.stdout)
                self.assertNotIn("device_secret", client.stdout)
                self.assertNotIn("sudo root", client.stdout)
                match = CODE.search(client.stdout)
                self.assertIsNotNone(match, "client did not present one device code")
                record = store.lookup(user_code=match.group(1),
                                      operator_subject="auth0|synthetic-ci-lookup")
                self.assertEqual(record["status"], "proven")
                self.assertEqual(record["access_mode"], "restricted")
                pair_dir = Path("/home/ai-gateway/.ssh/ai-lab-device-code")
                for name in ("tunnel-ed25519", "device-id"):
                    p = pair_dir / name
                    self.assertTrue(p.is_file())
                    self.assertEqual(p.stat().st_uid, pwd.getpwnam(USER).pw_uid)
                    self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
                self.assertEqual(pair_dir.stat().st_uid, pwd.getpwnam(USER).pw_uid)
                self.assertEqual(stat.S_IMODE(pair_dir.stat().st_mode), 0o700)
                # With --host-key the real sshd host identity is REUSED
                # as public data; no bogus per-client private host key exists.
                self.assertFalse((pair_dir / "host-ed25519").exists())
                self.assertTrue(HOST_KEY.is_file())
                self.assertFalse(Path("/home/ai-gateway/.ssh/authorized_keys").exists(),
                                 "unapproved pairing unexpectedly installed login access")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
