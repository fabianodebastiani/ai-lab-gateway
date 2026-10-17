"""Stage 6: restricted one-command installer and human-facing CLI wrapper.

Isolated checks only: no enrollment, no sudo, no real services changed.
"""
from pathlib import Path
import hashlib
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install_ai_lab_device.sh"


def wrapper_contents(script: str) -> str:
    begin = "cat > \"$wrapper\" <<'AI_LAB_HUMAN_CLI_WRAPPER'\n"
    end = "\nAI_LAB_HUMAN_CLI_WRAPPER\n"
    if script.count(begin) != 1:
        raise AssertionError("expected exactly one fixed human shortcut payload")
    return script.split(begin, 1)[1].split(end, 1)[0] + "\n"


class FirstRunInstallerTests(unittest.TestCase):
    def test_posix_shell_syntax(self):
        proc = subprocess.run(["sh", "-n", str(INSTALLER)],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_signed_root_executor_is_prepared_after_authenticated_pairing(self):
        source = INSTALLER.read_text()
        self.assertNotIn("NOPASSWD: ALL", source)
        self.assertNotIn("sudo bash", source)
        self.assertNotIn("curl | sudo", source)
        self.assertNotIn("chmod 777", source)
        self.assertIn("install_target_privexec.py", source)
        self.assertIn('download "$PRIVEXEC_INSTALL_URL" "$exec_installer"', source)
        self.assertIn('sha_check "$exec_installer" "$PRIVEXEC_INSTALL_SHA256"', source)
        self.assertIn('download "$PRIVEXEC_EXEC_URL" "$exec_source"', source)
        self.assertIn('sha_check "$exec_source" "$PRIVEXEC_EXEC_SHA256"', source)
        self.assertIn('sudo -- /usr/bin/python3 -I "$exec_installer"', source)
        self.assertIn('sudo -- /usr/bin/python3 "$helper"', source)
        self.assertIn("AI_LAB_PRIVEXEC_INSTALLED_DENY_ALL", source)
        self.assertIn("Nenhum sudo remoto/genérico", source)
        actual_pairing = source.index('    sudo -u ai-gateway -H -- env')
        actual_install = source.rindex('    prepare_privexec')
        self.assertLess(actual_pairing, actual_install)
        self.assertLess(actual_install, source.index('install -m 0700 "$wrapper" "$shortcut"'))

    def test_existing_device_upgrade_does_not_pair_again(self):
        source = INSTALLER.read_text()
        self.assertIn(' = "--upgrade-sudo" ]; then', source)
        self.assertLess(source.index(' = "--upgrade-sudo" ]; then'),
                        source.index('download "$CLIENT_URL" "$client"'))
        self.assertIn('device_id="$(sudo -- /usr/bin/cat '
                      '/home/ai-gateway/.ssh/ai-lab-device-code/device-id)"', source)
        self.assertNotIn("sudo usermod -aG sudo ai-gateway", source)

    def test_issuer_public_key_matches_independently_known_fingerprint(self):
        import base64
        source = INSTALLER.read_text()
        match = re.search(r'^ISSUER_PUBLIC_KEY="ssh-ed25519 ([A-Za-z0-9+/=]+)"$', source, re.M)
        fp = re.search(r'^ISSUER_FINGERPRINT="(SHA256:[A-Za-z0-9+/]+)"$', source, re.M)
        self.assertIsNotNone(match)
        self.assertIsNotNone(fp)
        binary = base64.b64decode(match.group(1))
        calculated = "SHA256:" + base64.b64encode(hashlib.sha256(binary).digest()).decode().rstrip("=")
        self.assertEqual(fp.group(1), calculated)

    def test_pins_remain_immutable(self):
        source = INSTALLER.read_text()
        for name in ("RELEASE_COMMIT", "LOCAL_SETUP_COMMIT", "LOCAL_CLI_COMMIT", "PRIVEXEC_COMMIT"):
            match = re.search(r'^' + name + r'="([a-f0-9]{40})"$', source, re.M)
            self.assertIsNotNone(match, name)
        for name in ("CLIENT_SHA256", "LOCAL_SETUP_SHA256", "LOCAL_CLI_SHA256", "PRIVEXEC_INSTALL_SHA256", "PRIVEXEC_EXEC_SHA256"):
            match = re.search(r'^' + name + r'="([a-f0-9]{64})"$', source, re.M)
            self.assertIsNotNone(match, name)
        self.assertIn("--proto '=https' --proto-redir '=https'", source)
        self.assertIn("wget --quiet --https-only", source)
        self.assertIn('download "$CLIENT_URL" "$client"', source)
        self.assertIn('download "$LOCAL_SETUP_URL" "$helper"', source)
        self.assertIn('download "$LOCAL_CLI_URL" "$local_cli"', source)

    def test_preflight_refuses_extra_options_without_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, HOME=tmp, TMPDIR=tmp)
            # The runner's ordinary non-root user can reach this preflight;
            # even on an unsupported Linux it must not create anything.
            for argv in (["--check", "--other"],):
                p = subprocess.run(["sh", str(INSTALLER), *argv],
                                   env=env, capture_output=True, text=True)
                self.assertNotEqual(p.returncode, 0)
                self.assertFalse(list(Path(tmp).iterdir()))

    def test_preflight_never_downloads_or_prompts_for_sudo(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, HOME=tmp, TMPDIR=tmp)
            proc = subprocess.run(["sh", str(INSTALLER), "--check"],
                                  env=env, capture_output=True, text=True, timeout=10)
            # A non-systemd CI container may legitimately fail the platform
            # prerequisites, but it must still avoid any files/downloads.
            self.assertNotIn("Código:", proc.stdout)
            self.assertFalse(list(Path(tmp).iterdir()))
            if proc.returncode == 0:
                self.assertIn("AI_LAB_INSTALL_PRECHECK_OK", proc.stdout)
            else:
                self.assertEqual(proc.returncode, 2)

    def test_human_wrapper_is_valid_posix_sh(self):
        wrapper = wrapper_contents(INSTALLER.read_text())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ailab"
            path.write_text(wrapper)
            proc = subprocess.run(["sh", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_human_wrapper_rejects_unknown_commands_before_sudo(self):
        wrapper = wrapper_contents(INSTALLER.read_text())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ailab"
            path.write_text(wrapper)
            for args in ([], ["--sudo"], ["status", "--root"],
                         ["status", ""], ["connect", ""],
                         ["persistent", "all"], ["connect", "shell"],
                         ["persistent", "on", "other"]):
                with self.subTest(args=args):
                    proc = subprocess.run(["sh", str(path), *args],
                                         capture_output=True, text=True, timeout=5)
                    self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_human_wrapper_runs_allowlisted_cli_as_restricted_user(self):
        wrapper = wrapper_contents(INSTALLER.read_text())
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            path = folder / "ailab"
            path.write_text(wrapper)
            fake_id = folder / "id"
            fake_id.write_text("#!/bin/sh\n"
                               "case \"$1:$2\" in -un:) echo laboperator;;"
                               " -u:ai-gateway) echo 1203;; *) exit 2;; esac\n")
            fake_id.chmod(0o700)
            fake_sudo = folder / "sudo"
            fake_sudo.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
            fake_sudo.chmod(0o700)
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ.get("PATH", ""))
            for args in (["status"], ["connect"], ["disconnect"],
                         ["persistent", "on"], ["persistent", "off"]):
                with self.subTest(args=args):
                    p = subprocess.run(["sh", str(path), *args], env=env,
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(p.returncode, 0, p.stderr)
                    lines = p.stdout.strip().splitlines()
                    self.assertEqual(lines[:5], ["-u", "ai-gateway", "-H", "--", "env"])
                    self.assertEqual(lines[5:8], [
                        "XDG_RUNTIME_DIR=/run/user/1203",
                        "/usr/bin/python3", "/home/ai-gateway/.local/bin/ailab"])
                    self.assertEqual(lines[8:], args)

    def test_verify_all_downloads_before_first_local_sudo(self):
        source = INSTALLER.read_text()
        # Both the local helper and the CLI must be downloaded and their
        # SHA-256 validated BEFORE the first root-authorized setup mutation.
        after = source.index('    if ! command -v sudo', source.index('if [ "$need_local_setup" = no ]; then'))
        part = source[after:]
        helper_check = part.index('"$helper" "$LOCAL_SETUP_SHA256"')
        cli_download = part.index('download "$LOCAL_CLI_URL" "$local_cli"')
        cli_check = part.index('"$local_cli" "$LOCAL_CLI_SHA256"')
        local_root = part.index('sudo -- /usr/bin/python3 "$helper"')
        self.assertLess(helper_check, cli_download)
        self.assertLess(cli_download, cli_check)
        self.assertLess(cli_check, local_root)

    def test_human_shortcut_is_only_published_after_pairing_success(self):
        source = INSTALLER.read_text()
        paired = source.index('    sudo -u ai-gateway -H -- env "XDG_RUNTIME_DIR=/run/user/$target_id"')
        publish = source.index('install -m 0700 "$wrapper" "$shortcut"')
        self.assertLess(paired, publish)
        self.assertIn("Only publish the human convenience shortcut after successful pairing", source)
        self.assertLess(source.index('atalho ailab existente'), paired)

    def test_human_shortcut_does_not_overwrite_existing_local_file(self):
        script = INSTALLER.read_text()
        self.assertIn('if [ -L "$HOME/.local" ] || [ -L "$HOME/.local/bin" ]', script)
        self.assertIn('if [ -e "$shortcut" ] || [ -L "$shortcut" ]', script)
        self.assertIn('! cmp -s "$wrapper" "$shortcut"', script)
        self.assertIn('install -m 0700 "$wrapper" "$shortcut"', script)


if __name__ == "__main__":
    unittest.main()
