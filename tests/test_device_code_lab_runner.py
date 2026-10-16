"""Process-level test for the complete isolated device code laboratory."""
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import unittest

from ai_lab_gateway.device_code_operator import call_operator_lookup, call_operator_confirm_single_code


ROOT=Path(__file__).resolve().parents[1]
RUNNER=ROOT/"scripts"/"run_device_code_lab.py"
CLIENT=ROOT/"scripts"/"device_code_pair_linux.py"


class LabServerTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.host=self.root/"ssh_host_ed25519_key"
        subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","",
                        "-f",str(self.host)],check=True,capture_output=True)

    def test_two_processes_http_pairing_and_separate_unix_lookup(self):
        state=self.root/"private-state"
        env=dict(os.environ)
        env["PYTHONPATH"]=str(ROOT/"src")
        process=subprocess.Popen(
            [sys.executable,str(RUNNER),
             "--state-dir",str(state),"--port","0","--lab-only"],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            text=True,bufsize=1,env=env,start_new_session=True)
        try:
            http=process.stdout.readline().strip()
            ipc=process.stdout.readline().strip()
            banner=process.stdout.readline().strip()
            self.assertRegex(http,r"^LAB_HTTP_URL=http://127[.]0[.]0[.]1:\d+$")
            self.assertRegex(ipc,r"^LAB_OPERATOR_SOCKET=")
            self.assertIn("LAB_ONLY",banner)
            origin=http.split("=",1)[1]
            socket=Path(ipc.split("=",1)[1])
            result=subprocess.run(
                [sys.executable,"-S",str(CLIENT),
                 "--base-url",origin,
                 "--device-id","new-linux-process-01",
                 "--name","Linux de outra máquina",
                 "--state-dir",str(self.root/"new-user-ssh"/"device-code"),
                 "--no-wait"],
                capture_output=True,text=True,timeout=18,check=False,env=env)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("Conectar dispositivo",result.stdout)
            self.assertTrue((self.root/"new-user-ssh"/"device-code"/"host-ed25519").is_file())
            self.assertTrue((self.root/"new-user-ssh"/"device-code"/"host-ed25519.pub").is_file())
            code=re.search(r"Código: ([A-Z2-9]{4}-[A-Z2-9]{4})",
                           result.stdout).group(1)
            found=call_operator_lookup(path=socket,
                       subject="auth0|staging-demo",user_code=code)
            self.assertEqual(found["status"],"awaiting_human_confirmation")
            self.assertEqual(found["access_mode"],"restricted")
            self.assertNotIn("confirmation",found)
            self.assertNotIn("Confirmação:",result.stdout)
            approved=call_operator_confirm_single_code(
                path=socket,subject="auth0|staging-demo",
                request_id=found["request_id"],user_code=code)
            self.assertEqual(approved["status"],"approved")
            self.assertEqual(approved["access_mode"],"restricted")
            self.assertEqual(stat.S_IMODE(state.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((state/"hmac.key").stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE((state/"device-code.sqlite").stat().st_mode),0o600)
        finally:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGINT)
            try:
                process.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL)
                process.communicate(timeout=3)
        self.assertFalse(socket.exists())

    def test_lab_runner_rejects_default_without_explicit_opt_in(self):
        env=dict(os.environ)
        env["PYTHONPATH"]=str(ROOT/"src")
        proc=subprocess.run(
            [sys.executable,str(RUNNER),"--state-dir",str(self.root/"state")],
            capture_output=True,text=True,timeout=5,env=env)
        self.assertNotEqual(proc.returncode,0)
        self.assertFalse((self.root/"state").exists())


if __name__=="__main__":
    unittest.main()
