"""Safety tests for Oracle-side WSL v2 CANDIDATE provisioning (no root required)."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "provision_wsl_pairing_candidate_oracle.py"


def load():
    spec = importlib.util.spec_from_file_location("wsl_candidate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProvisionSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.root = root
        self.mod = load()
        a,b = root/"a",root/"b"
        for name in (a,b):
            subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","",
                            "-f",str(name)],check=True,capture_output=True)
        self.tunnel = a.with_suffix(".pub").read_text().strip()
        self.host = b.with_suffix(".pub").read_text().strip()
        self.request = {
            "status":"approved","device_id":"windows-wsl","persistent":False,
            "access_mode":"restricted","request_id":"A"*24,
            "reviewed_at":1000,
            "tunnel_public_key":self.tunnel,"ssh_host_public_key":self.host,
        }

    def test_human_approval_is_required_and_short_lived(self):
        self.assertEqual(self.mod.validate_approved(self.request,now=1001)["device_id"],
                         "windows-wsl")
        for changes in (
            {"status":"pending"}, {"status":"denied"},
            {"access_mode":"unrestricted"}, {"persistent":True},
            {"device_id":"oracle-gateway"}, {"reviewed_at":None},
        ):
            with self.subTest(changes=changes),self.assertRaises(PermissionError):
                self.mod.validate_approved({**self.request,**changes},now=1001)
        with self.assertRaises(PermissionError):
            self.mod.validate_approved(self.request,now=4601)

    def test_key_separation_mandatory(self):
        with self.assertRaises(ValueError):
            self.mod.validate_approved({**self.request,
                 "ssh_host_public_key":self.tunnel},now=1001)

    def test_wrong_key_type_rejected(self):
        with self.assertRaises(ValueError):
            self.mod.validate_approved({**self.request,
                 "tunnel_public_key":"ssh-rsa AAAA"},now=1001)

    def test_candidate_provision_isolated_and_keeps_legacy_registry(self):
        m=self.mod
        base=self.root/"isolated"
        base.mkdir()
        tunnel=base/"authorized_keys"
        known=base/"known_hosts"
        registry=base/"devices.json"
        keys=base/"keys"
        candidates=base/"candidates"
        backup=base/"backups"
        keys.mkdir()
        backup.mkdir()
        tunnel.write_text('permitlisten="127.0.0.1:10002" ssh-ed25519 OLD-TUNNEL\\n')
        known.write_text("[127.0.0.1]:10002 ssh-ed25519 OLD-HOST\\n")
        tunnel.chmod(0o600)
        known.chmod(0o600)
        registry.write_text(json.dumps({"devices":[{"id":"windows-wsl","tunnel_port":10002}]}))
        original=registry.read_bytes()
        uid=os.getuid()
        gid=os.getgid()
        patches=[
            patch.object(m,"TUNNEL_KEYS",tunnel),
            patch.object(m,"GATEWAY_KNOWN",known),
            patch.object(m,"REGISTRY",registry),
            patch.object(m,"GATEWAY_KEYS",keys),
            patch.object(m,"CANDIDATES",candidates),
            patch.object(m,"BACKUPS",backup),
            patch.object(m.os,"geteuid",return_value=0),
            patch.object(m.os,"chown",return_value=None),
            patch.object(m.os,"fchown",return_value=None),
            patch.object(m.pwd,"getpwnam",return_value=SimpleNamespace(pw_uid=uid,pw_gid=gid)),
            patch.object(m.time,"time",return_value=1001),
        ]
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in patches: stack.enter_context(item)
            result=m.prepare(self.request)
        self.assertEqual(result["status"],"candidate_prepared")
        self.assertEqual(result["port"],10003)
        self.assertEqual(registry.read_bytes(),original)
        self.assertIn("10002",tunnel.read_text())
        self.assertIn("10003",tunnel.read_text())
        self.assertIn(self.tunnel.split()[1],tunnel.read_text())
        self.assertIn("10003",known.read_text())
        self.assertIn(self.host.split()[1],known.read_text())
        self.assertTrue((keys/"windows-wsl-v2-candidate").is_file())
        self.assertEqual((keys/"windows-wsl-v2-candidate").stat().st_mode & 0o777,0o600)
        self.assertEqual((candidates/"windows-wsl.json").stat().st_mode & 0o777,0o600)
        self.assertIn("OLD-TUNNEL",next(backup.glob("*/authorized_keys.original")).read_text())
        self.assertIn("OLD-HOST",next(backup.glob("*/known_hosts.original")).read_text())

    def test_candidate_preflight_does_not_modify_production(self):
        m=self.mod
        paths = {
            "tunnel":self.root/"tunnel_authorized_keys",
            "host":self.root/"known_hosts",
            "registry":self.root/"devices.json",
            "keys":self.root/"keys",
            "candidates":self.root/"candidates",
        }
        paths["tunnel"].write_text('permitlisten="127.0.0.1:10002" ssh-ed25519 EXISTING\n')
        paths["host"].write_text("[127.0.0.1]:10002 ssh-ed25519 EXISTING\n")
        paths["tunnel"].chmod(0o600)
        paths["host"].chmod(0o600)
        paths["registry"].write_text(json.dumps({"devices":[{
            "id":"windows-wsl","tunnel_port":10002
        }]}))
        paths["keys"].mkdir()
        patches=[
            patch.object(m,"TUNNEL_KEYS",paths["tunnel"]),
            patch.object(m,"GATEWAY_KNOWN",paths["host"]),
            patch.object(m,"REGISTRY",paths["registry"]),
            patch.object(m,"GATEWAY_KEYS",paths["keys"]),
            patch.object(m,"CANDIDATES",paths["candidates"]),
            patch.object(m.os,"geteuid",return_value=0),
            patch.object(m.pwd,"getpwnam",return_value=SimpleNamespace(
                pw_uid=os.getuid(),pw_gid=os.getgid())),
            patch.object(m.time,"time",return_value=1001),
        ]
        with patches[0],patches[1],patches[2],patches[3],patches[4],patches[5],patches[6],patches[7]:
            result=m.candidate_preflight(self.request)
        self.assertEqual(result[3],paths["keys"]/"windows-wsl-v2-candidate")
        self.assertEqual(paths["tunnel"].read_text(),
                         'permitlisten="127.0.0.1:10002" ssh-ed25519 EXISTING\n')
        self.assertEqual(paths["host"].read_text(),
                         "[127.0.0.1]:10002 ssh-ed25519 EXISTING\n")
        self.assertFalse(paths["candidates"].exists())


if __name__=="__main__":
    unittest.main()
