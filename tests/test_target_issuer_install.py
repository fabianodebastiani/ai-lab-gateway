"""Root-only disposable signer bootstrap tests: no host /etc modifications."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

P = Path(__file__).resolve().parents[1] / "scripts" / "install_target_issuer.py"
loader = importlib.machinery.SourceFileLoader("synthetic_issuer_installer", str(P))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


@unittest.skipUnless(os.geteuid() == 0, "root only on disposable CI")
class GatewayIssuerInstall(unittest.TestCase):
    def setUp(self):
        self.ctx = tempfile.TemporaryDirectory()
        self.addCleanup(self.ctx.cleanup)
        self.root = Path(self.ctx.name)
        self.registry = self.root / "devices.json"
        self.issuer = self.root / "issuer"
        self.device = "ai-lab-experiments-01-fd3dab34"
        self.registry.write_text(json.dumps({"devices": [{
            "id": self.device, "enabled": True, "ssh_user": "ai-gateway",
            "tunnel_host": "127.0.0.1", "tunnel_port": 11000}]}))
        self.registry.chmod(0o640)
        m = patch.multiple(module, REGISTRY=self.registry,
                           ISSUER_DIR=self.issuer)
        m.start()
        self.addCleanup(m.stop)

    def test_check_only_does_not_generate_key(self):
        self.assertIn("DRY_RUN_OK", module.install(self.device, plan=True))
        self.assertFalse(self.issuer.exists())

    def test_root_signer_generation_is_only_one_target_and_not_overwritten(self):
        message = module.install(self.device, plan=False)
        self.assertIn("ISSUER_PREPARED", message)
        self.assertEqual(stat.S_IMODE(self.issuer.stat().st_mode), 0o700)
        private = self.issuer / "issuer_ed25519"
        self.assertTrue(private.read_bytes().startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
        self.assertEqual(json.loads((self.issuer / "targets.json").read_text()),
                         {"version": 1, "devices": [self.device]})
        with self.assertRaises(FileExistsError):
            module.install(self.device, plan=False)
        self.assertTrue(private.exists())

    def test_reject_unregistered_disabled_or_wrong_linux_account(self):
        with self.assertRaises(PermissionError):
            module.install("raspberry-lab", plan=True)
        data = json.loads(self.registry.read_text())
        data["devices"][0]["ssh_user"] = "root"
        self.registry.write_text(json.dumps(data))
        with self.assertRaises(PermissionError):
            module.install(self.device, plan=True)
        self.assertFalse(self.issuer.exists())

    def test_symlinked_or_world_write_registry_fails(self):
        self.registry.chmod(0o666)
        with self.assertRaises(PermissionError):
            module.install(self.device, plan=True)
        self.registry.chmod(0o640)
        old = self.root / "actual"
        self.registry.rename(old)
        self.registry.symlink_to(old)
        with self.assertRaises(PermissionError):
            module.install(self.device, plan=True)


if __name__ == "__main__":
    unittest.main()
