"""Isolated auth-boundary tests: operator UNIX lookup cannot self-approve."""
import base64
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives import serialization

from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_operator import (
    OperatorProtocol, create_operator_socket, call_operator_lookup,
    call_operator_confirm,
)


class OperatorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.store = DeviceCodeStore(self.root/"code.sqlite",hmac_key=b"O"*32)
        keys=[]
        for role in ("tunnel", "host"):
            private = self.root/role
            subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","",
                            "-f",str(private)],check=True,capture_output=True)
            keys.append((private,Path(str(private)+".pub").read_text().strip()))
        self.keys=keys
        self.runtime=self.root/"runtime"
        self.runtime.mkdir(mode=0o700)
        self.path=self.runtime/"operator.sock"

    def prove(self):
        p=self.store.start(device_id="fresh-test-linux",
                display_name="Fresh Linux", source_id="192.0.2.55",
                tunnel_public_key=self.keys[0][1],
                host_public_key=self.keys[1][1],persistent=False)
        signer=serialization.load_ssh_private_key(self.keys[0][0].read_bytes(),None)
        signature=base64.b64encode(signer.sign(
                base64.b64decode(p["challenge_b64"]))).decode()
        self.store.prove(request_id=p["request_id"],
                         device_secret=p["device_secret"],
                         signature_b64=signature)
        return p

    def serve(self, uid=None):
        server=create_operator_socket(self.path, self.store,
                     allowed_gateway_uid=os.geteuid() if uid is None else uid)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(thread.join,3)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_real_unix_peer_looks_up_code_no_admin_grant(self):
        p=self.prove()
        self.serve()
        result=call_operator_lookup(path=self.path,subject="auth0|operator",
                                    user_code=p["user_code"])
        self.assertEqual(result["request_id"],p["request_id"])
        self.assertEqual(result["access_mode"],"restricted")
        self.assertNotIn("confirmation",result)
        self.assertNotIn("device_secret",result)
        self.assertNotIn("tunnel_public_key",result)
        with self.assertRaises(PermissionError):
            call_operator_lookup(path=self.path,subject="auth0|another",
                                 user_code=p["user_code"])
        # A bare AI text affirmation cannot satisfy the terminal-only code.
        with self.assertRaises(PermissionError):
            call_operator_confirm(path=self.path, subject="auth0|operator",
                  request_id=p["request_id"], confirmation="AAAA-AAAA")
        approved=call_operator_confirm(path=self.path, subject="auth0|operator",
                  request_id=p["request_id"], confirmation=p["confirmation"])
        self.assertEqual(approved["status"],"approved")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)

    def test_fake_peer_uid_is_rejected_before_json_or_subject(self):
        self.prove()
        self.serve(uid=os.geteuid()+12345)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(str(self.path))
            sock.sendall(b'{"action":"lookup","subject":"auth0|victim","user_code":"FAKE-FAKE"}\n')
            reply=json.loads(sock.recv(1024))
        self.assertEqual(reply,{"ok":False,"error":"unauthorized_peer"})

    def test_approval_and_provision_actions_not_implemented(self):
        op=OperatorProtocol(self.store)
        for action in ("approve","activate","root","enroll"):
            self.assertEqual(op.dispatch({
                "action":action,"subject":"auth0|user",
                "user_code":"ABCD-EFGH"
            }),{"ok":False,"error":"unsupported"})
        self.assertEqual(op.dispatch({
            "action":"lookup","subject":"auth0|user",
            "user_code":"ABCD-EFGH","consent_verified":True
        }),{"ok":False,"error":"invalid_request"})

    def test_insecure_runtime_and_existing_socket_are_rejected(self):
        self.prove()
        self.runtime.chmod(0o755)
        with self.assertRaises(PermissionError):
            create_operator_socket(self.path,self.store,
                                   allowed_gateway_uid=os.geteuid())
        self.runtime.chmod(0o700)
        self.path.write_text("not a socket")
        with self.assertRaises(PermissionError):
            create_operator_socket(self.path,self.store,
                                   allowed_gateway_uid=os.geteuid())


if __name__=="__main__":
    unittest.main()
