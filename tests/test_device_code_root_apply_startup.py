"""Default OFF root-apply command and marker are independent of preflight."""
import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run_device_code_root_apply.py"
spec = importlib.util.spec_from_file_location("candidate_root_apply_runner", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class Marker:
    def __init__(self, text="SSH_10003_CANDIDATE_ONLY_V1",
                 owner=0, mode=0o400, links=1, directory=False):
        self.content = text
        self.info = SimpleNamespace(
            st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | mode,
            st_uid=owner, st_nlink=links)

    def lstat(self):
        return self.info

    def read_text(self, *, encoding):
        self.__class__.__name__
        return self.content


class CandidateRootStartupTests(unittest.TestCase):
    def test_nonroot_process_cannot_enable_root_apply(self):
        with patch.object(runner.os, "geteuid", return_value=1000):
            with self.assertRaises(PermissionError):
                runner.check_supervised_enablement()

    def test_no_root_marker_means_no_service(self):
        with patch.object(runner.os, "geteuid", return_value=0):
            with patch.object(runner, "MARKER",
                              Path("/nonexistent/ai-lab-root-apply-marker")):
                with self.assertRaises(FileNotFoundError):
                    runner.check_supervised_enablement()

    def test_wrong_marker_owner_mode_hardlinks_or_content_are_refused(self):
        for marker in (
            Marker(owner=1000), Marker(mode=0o600),
            Marker(mode=0o644), Marker(links=2),
            Marker(directory=True),
            Marker(text="READ_ONLY_PREFLIGHT_V1"),
            Marker(text="SSH_10003_ROOT_NOW"), Marker(text=""),
        ):
            with self.subTest(marker=marker):
                with patch.object(runner.os, "geteuid", return_value=0), \
                     patch.object(runner, "MARKER", marker):
                    with self.assertRaises(PermissionError):
                        runner.check_supervised_enablement()

    def test_only_independently_prepared_root_marker_passes(self):
        with patch.object(runner.os, "geteuid", return_value=0), \
             patch.object(runner, "MARKER", Marker()):
            runner.check_supervised_enablement()

    def test_apply_only_service_does_not_expose_cutover_or_sudo(self):
        from ai_lab_gateway.device_code_root_apply import RootApplyProtocol
        protocol = RootApplyProtocol(lambda request: {
            "status": "candidate_ssh_staged", "port": 10003,
            "registry_changed": False, "sudo_granted": False})
        for action in ("cutover", "root", "sudo", "write_file",
                       "activate", "revoke", "shutdown", "ssh"):
            self.assertEqual(protocol.dispatch({
                "action": action, "request_id": "A" * 26}),
                {"ok": False, "error": "unsupported"})


if __name__ == "__main__":
    unittest.main()
