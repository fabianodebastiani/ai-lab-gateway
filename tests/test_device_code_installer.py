"""Pre-release Linux installer: pinned HTTPS artifact, no root, no sshd."""
from pathlib import Path
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import unittest

from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_http import run_device_code_server

ROOT=Path(__file__).resolve().parents[1]
INSTALLER=ROOT/"scripts"/"install_ai_lab_device.sh"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.db=DeviceCodeStore(self.root/"server.sqlite", hmac_key=b"V"*32)
        self.server=run_device_code_server(self.db)
        thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(thread.join,3)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.origin="http://127.0.0.1:"+str(self.server.server_port)

    def test_download_hash_then_enroll_auto_id_clean_home(self):
        # No Python cryptography setup on target, no old device files,
        # no known device ID, no sshd/host key required, and no sudo.
        home=self.root/"empty-user-home"
        home.mkdir(mode=0o700)
        env=dict(os.environ, HOME=str(home))
        result=subprocess.run(["sh",str(INSTALLER),"--base-url",self.origin,
                               "--no-wait"],
                              capture_output=True,text=True,timeout=35,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("hash SHA-256 validado",result.stdout)
        self.assertIn("Código:",result.stdout)
        self.assertIn("Confirmação:",result.stdout)
        self.assertNotIn("device_secret",result.stdout)
        self.assertTrue(re.search(r"Código: [A-Z2-9]{4}-[A-Z2-9]{4}",result.stdout))
        local=home/".ssh"/"ai-lab-device-code"
        self.assertEqual(stat.S_IMODE((home/".ssh").stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE(local.stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE((local/"device-id").stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE((local/"tunnel-ed25519").stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE((local/"host-ed25519").stat().st_mode),0o600)
        device_id=(local/"device-id").read_text().strip()
        self.assertTrue(re.fullmatch(r"[a-z][a-z0-9-]{2,47}",device_id))
        self.assertEqual(self.db.lookup(user_code=re.search(
               r"Código: ([A-Z2-9]{4}-[A-Z2-9]{4})",result.stdout).group(1),
               operator_subject="auth0|lab")["device_id"],device_id)

    def test_changed_pinned_sha256_fails_before_execute(self):
        original=INSTALLER.read_text()
        match=re.search(r'CLIENT_SHA256="([a-f0-9]{64})"',original)
        self.assertIsNotNone(match)
        mutated=original.replace(match.group(1),"0"*64,1)
        bad=self.root/"modified-bootstrap.sh"
        bad.write_text(mutated)
        home=self.root/"unused-home"
        home.mkdir(mode=0o700)
        env=dict(os.environ,HOME=str(home))
        proc=subprocess.run(["sh",str(bad),"--base-url",self.origin,"--no-wait"],
                    capture_output=True,text=True,timeout=30,env=env)
        self.assertEqual(proc.returncode,3,proc.stderr)
        self.assertIn("HASH INCORRETO",proc.stderr)
        self.assertFalse((home/".ssh").exists())


if __name__=="__main__":
    unittest.main()
