"""Root preflight is OFF by default and cannot install SSH or activate tunnels."""
import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ENTRY = Path(__file__).resolve().parents[1] / "scripts/run_device_code_root_preflight.py"
spec = importlib.util.spec_from_file_location("root_preflight_entry_for_tests", ENTRY)
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


class _FakeProtectedMarker:
    def __init__(self, *, text="READ_ONLY_PREFLIGHT_V1",
                 uid=0, mode=0o400, nlink=1):
        self.body = text
        self.stat = SimpleNamespace(st_mode=stat.S_IFREG | mode,
                                    st_uid=uid, st_nlink=nlink)

    def lstat(self):
        return self.stat

    def read_text(self, encoding):
        return self.body


class RootReadOnlyStartupTests(unittest.TestCase):
    def test_no_nonroot_service_activation(self):
        with patch.object(entry.os, "geteuid", return_value=1000):
            with self.assertRaises(PermissionError):
                entry.check_opt_in()

    def test_missing_enable_marker_rejected(self):
        with patch.object(entry.os, "geteuid", return_value=0):
            with patch.object(entry, "ENABLED",
                              Path("/nonexistent/never-authorized-marker")):
                with self.assertRaises(FileNotFoundError):
                    entry.check_opt_in()

    def test_wrong_owner_mode_content_or_hardlink_rejected(self):
        markers = (
            _FakeProtectedMarker(uid=1000),
            _FakeProtectedMarker(mode=0o644),
            _FakeProtectedMarker(nlink=2),
            _FakeProtectedMarker(text="APPLY_SSH_NOW"),
            _FakeProtectedMarker(text=""),
        )
        for marker in markers:
            with self.subTest(marker=marker):
                with patch.object(entry.os, "geteuid", return_value=0), patch.object(
                        entry, "ENABLED", marker):
                    with self.assertRaises(PermissionError):
                        entry.check_opt_in()

    def test_only_exact_protected_readonly_marker_passes(self):
        marker = _FakeProtectedMarker()
        with patch.object(entry.os, "geteuid", return_value=0), patch.object(
                entry, "ENABLED", marker):
            entry.check_opt_in()

    def test_no_apply_or_activate_interface_in_root_protocol(self):
        from ai_lab_gateway.device_code_root_preflight_rpc import RootPreflightProtocol
        protocol = RootPreflightProtocol(
            trusted_approval_reader=lambda request: {"approved": True},
            trusted_environment_probe=lambda value: {
                "status": "candidate_preflight_ok", "port": 10003,
                "ssh_changed": False, "registry_changed": False})
        for command in ("apply", "provision", "activate", "execute", "write_file"):
            self.assertEqual(protocol.dispatch({
                "action": command, "request_id": "A" * 26}),
                {"ok": False, "error": "unsupported"})


if __name__ == "__main__":
    unittest.main()
