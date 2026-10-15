"""Read-only root installer environment checks with isolated synthetic files."""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ai_lab_gateway.device_code_root_environment import (
    check_tunnel_sshd_policy, inspect_candidate_environment,
    inspect_fixed_production_environment, known_hosts_key,
    loopback_port_available, protected_file,
)
from ai_lab_gateway.device_code_offer import OFFER_VERSION, fingerprint


SSHD = """
authenticationmethods publickey
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
allowtcpforwarding remote
gatewayports no
x11forwarding no
allowagentforwarding no
permittty no
permituserrc no
maxsessions 0
"""


class FixedRootEnvironmentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.keys = {}
        for kind in ("tunnel", "host", "gateway", "management", "different"):
            key = self.root / kind
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519",
                            "-N", "", "-f", str(key)], check=True, capture_output=True)
            self.keys[kind] = " ".join(
                Path(str(key) + ".pub").read_text("ascii").split()[:2])
        self.request_id = "A" * 26
        offer = {
            "version": OFFER_VERSION, "request_id": self.request_id,
            "device_id": "windows-wsl", "access_mode": "restricted",
            "persistent": False, "gateway_host": "gateway.debasti.com",
            "gateway_ssh_port": 22, "gateway_tunnel_user": "tunnel",
            "gateway_ssh_host_key": self.keys["gateway"],
            "gateway_management_public_key": self.keys["management"],
            "reverse_listen_host": "127.0.0.1",
            "reverse_listen_port": 10003, "management_user": "ai-gateway",
            "device_tunnel_fingerprint": fingerprint(self.keys["tunnel"]),
            "device_host_fingerprint": fingerprint(self.keys["host"]),
        }
        self.candidate = {
            "request_id": self.request_id, "device_id": "windows-wsl",
            "access_mode": "restricted", "persistent": False,
            "tunnel_public_key": self.keys["tunnel"],
            "host_public_key": self.keys["host"], "offer": offer,
        }
        self.files = {}
        data = {
            "authorized_keys":
                'permitlisten="127.0.0.1:10002" ssh-ed25519 old-legacy\n',
            "known_hosts": "[127.0.0.1]:10002 " + self.keys["host"] + "\n",
            "registry": ('{"devices":[{"id":"raspberry-lab","tunnel_port":10001},'
                         '{"id":"windows-wsl","tunnel_port":10002}]}'),
            "gateway_host_key": self.keys["gateway"] + "\n",
            "management_key": self.keys["management"] + "\n",
        }
        for name, value in data.items():
            folder = self.root / ("trusted-" + name)
            folder.mkdir(mode=0o700)
            target = folder / "source"
            target.write_text(value, encoding="ascii")
            target.chmod(0o600)
            self.files[name] = target
        # Distinct private/public management identity, never sent to offer.
        self.files["management_private_key"] = self.root / "management"
        self.owners = dict.fromkeys(("tunnel", "gateway", "registry", "host"), os.getuid())

    def inspect(self, *, candidate=None, sshd=SSHD, free=True,
                files=None, owners=None):
        return inspect_candidate_environment(
            self.candidate if candidate is None else candidate,
            files=self.files if files is None else files,
            owners=self.owners if owners is None else owners,
            effective_sshd=sshd, port_is_free=free)

    def test_secure_exact_environment_can_only_preflight(self):
        result = self.inspect()
        self.assertEqual(result["status"], "candidate_preflight_ok")
        self.assertEqual(result["port"], 10003)
        self.assertFalse(result["ssh_changed"])
        self.assertFalse(result["registry_changed"])
        self.assertFalse(result["persistent"])

    def test_rejects_untrusted_file_modes_and_parent_ownership(self):
        file = self.files["authorized_keys"]
        file.chmod(0o666)
        with self.assertRaises(PermissionError):
            self.inspect()
        file.chmod(0o600)
        parent = file.parent
        parent.chmod(0o777)
        with self.assertRaises(PermissionError):
            self.inspect()
        parent.chmod(0o700)
        wrong = {**self.owners, "tunnel": os.getuid() + 1}
        with self.assertRaises(PermissionError):
            self.inspect(owners=wrong)

    def test_rejects_ssh_file_symlinks_without_following_them(self):
        file = self.files["gateway_host_key"]
        alias = file.parent / "symlink"
        alias.symlink_to(file)
        changed = {**self.files, "gateway_host_key": alias}
        with self.assertRaises((PermissionError, OSError)):
            self.inspect(files=changed)
        self.assertEqual(file.read_text().strip(), self.keys["gateway"])

    def test_rejects_changed_gateway_host_and_management_keys(self):
        self.files["gateway_host_key"].write_text(self.keys["different"] + "\n")
        with self.assertRaises(PermissionError):
            self.inspect()
        self.files["gateway_host_key"].write_text(self.keys["gateway"] + "\n")
        self.files["management_key"].write_text(self.keys["different"] + "\n")
        with self.assertRaises(PermissionError):
            self.inspect()

    def test_private_management_identity_must_match_offered_public_key(self):
        private_path = self.files["management_private_key"]
        other_private = self.root / "different"
        wrong = {**self.files, "management_private_key": other_private}
        with self.assertRaises(PermissionError):
            self.inspect(files=wrong)
        original_mode = stat.S_IMODE(private_path.stat().st_mode)
        private_path.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.inspect()
        private_path.chmod(original_mode)
        self.assertEqual(self.inspect()["status"], "candidate_preflight_ok")

    def test_rejects_target_host_key_substitution_and_duplicate_pins(self):
        file = self.files["known_hosts"]
        file.write_text("[127.0.0.1]:10002 " + self.keys["different"] + "\n")
        with self.assertRaises(PermissionError):
            self.inspect()
        file.write_text("[127.0.0.1]:10002 " + self.keys["host"] + "\n" +
                        "[127.0.0.1]:10002 " + self.keys["different"] + "\n")
        with self.assertRaises(PermissionError):
            self.inspect()
        self.assertEqual(
            known_hosts_key(("[127.0.0.1]:10002 " + self.keys["host"] + "\n").encode(),
                            endpoint="[127.0.0.1]:10002"), self.keys["host"])

    def test_rejects_occupied_port_and_bad_effective_sshd(self):
        with self.assertRaises(PermissionError):
            self.inspect(free=False)
        for altered in (
            SSHD.replace("allowtcpforwarding remote", "allowtcpforwarding yes"),
            SSHD.replace("maxsessions 0", "maxsessions 10"),
            SSHD.replace("passwordauthentication no", "passwordauthentication yes"),
            SSHD.replace("authenticationmethods publickey",
                         "authenticationmethods password"),
        ):
            with self.subTest(altered=altered), self.assertRaises(PermissionError):
                self.inspect(sshd=altered)
        with self.assertRaises(PermissionError):
            loopback_port_available(bind_port=10002)

    def test_root_verified_management_public_key_can_replace_old_test_layout(self):
        public = self.keys["management"]
        files = {k: v for k, v in self.files.items()
                 if k not in ("management_key", "management_private_key")}
        accepted = inspect_candidate_environment(
            self.candidate, files=files, owners=self.owners,
            effective_sshd=SSHD, port_is_free=True,
            root_verified_management_public_key=public)
        self.assertEqual(accepted["status"], "candidate_preflight_ok")
        with self.assertRaises(PermissionError):
            inspect_candidate_environment(
                self.candidate, files=files, owners=self.owners,
                effective_sshd=SSHD, port_is_free=True,
                root_verified_management_public_key=self.keys["different"])

    def test_rejects_live_registry_reassignment_without_modification(self):
        file = self.files["registry"]
        before = file.read_text()
        file.write_text('{"devices":[{"id":"windows-wsl","tunnel_port":10003}]}')
        with self.assertRaises(PermissionError):
            self.inspect()
        self.assertNotEqual(before, file.read_text())
        file.write_text(before)
        self.assertEqual(self.inspect()["port"], 10003)

    def test_production_entrypoint_requires_actual_root(self):
        with patch("ai_lab_gateway.device_code_root_environment.os.geteuid", return_value=1000):
            with self.assertRaises(PermissionError):
                inspect_fixed_production_environment(self.candidate, effective_sshd=SSHD)

    def test_secure_read_never_mutates_trusted_files(self):
        before = {key: path.read_bytes() for key, path in self.files.items()}
        self.inspect()
        self.assertEqual(before, {key: path.read_bytes() for key, path in self.files.items()})
        for path in self.files.values():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
