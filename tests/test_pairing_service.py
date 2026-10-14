"""Dual-UID pairing service: MCP issues invites but cannot approve."""
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import socket
import tempfile
from threading import Thread
import unittest

from ai_lab_gateway.enrollment import EnrollmentStore
from test_enrollment import public_key


def module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "pairing_service.py"
    loader = SourceFileLoader("pairing_service_under_test", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    imported = importlib.util.module_from_spec(spec)
    loader.exec_module(imported)
    return imported


class PairingRPCTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.service=module()
        self.store=EnrollmentStore(Path(self.tmp.name) / "invites.db")
        self.app=self.service.PairingRPC(self.store)

    def request_claim(self, token):
        return self.store.claim(token, device_id="windows-wsl-v2",
                                device_name="WSL Candidate",
                                tunnel_public_key=public_key(1),
                                ssh_host_public_key=public_key(2),
                                persistent=False)

    def test_mcp_can_create_request_but_cannot_approve(self):
        start=self.app.dispatch("mcp",{"action":"invite","subject":"oauth-user"})
        self.assertTrue(start["ok"])
        request=self.request_claim(start["token"])
        rid=request["request_id"]
        denied=self.app.dispatch("mcp",{
            "action":"approve","subject":"oauth-user","request_id":rid
        })
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"],"unsupported")
        self.assertEqual(self.store.inspect(rid)["status"],"pending")

    def test_approver_cannot_issue_invites_or_activate(self):
        self.assertFalse(self.app.dispatch("approver",{"action":"invite"})["ok"])
        self.assertFalse(self.app.dispatch("approver",{"action":"activate"})["ok"])

    def test_independent_review_only_approver_role(self):
        token=self.app.dispatch("mcp",{"action":"invite","subject":"oauth-user"})["token"]
        rid=self.request_claim(token)["request_id"]
        queue=self.app.dispatch("approver",{"action":"list"})
        self.assertEqual(queue["requests"][0]["request_id"],rid)
        done=self.app.dispatch("approver",{"action":"approve","request_id":rid})
        self.assertTrue(done["ok"])
        self.assertEqual(done["status"],"approved")
        self.assertEqual(self.store.inspect(rid)["status"],"approved")

    def test_oauth_subject_cannot_read_others_pairing(self):
        token=self.app.dispatch("mcp",{"action":"invite","subject":"alice"})["token"]
        rid=self.request_claim(token)["request_id"]
        good=self.app.dispatch("mcp",{"action":"status","subject":"alice",
                                      "request_id":rid})
        self.assertTrue(good["ok"])
        self.assertNotIn("tunnel_public_key",good["request"])
        bad=self.app.dispatch("mcp",{"action":"status","subject":"bob",
                                     "request_id":rid})
        self.assertFalse(bad["ok"])
        self.assertEqual(self.app.dispatch("mcp",{
            "action":"list_mine","subject":"bob"})["requests"],[])

    def test_unapproved_cannot_activated_by_root(self):
        token=self.app.dispatch("mcp",{"action":"invite","subject":"alice"})["token"]
        rid=self.request_claim(token)["request_id"]
        denied=self.app.dispatch("root",{
            "action":"activate","request_id":rid,
            "ssh_host_public_key":public_key(2),
            "tunnel_public_key":public_key(1),
        })
        self.assertFalse(denied["ok"])

    def test_unix_peer_uid_enforced(self):
        path=Path(self.tmp.name)/"mcp.sock"
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        sock.bind(str(path))
        sock.listen(3)
        handler=self.service.unix_handler(
            self.app,role="mcp",expected_uid=os.getuid()+999
        )
        with self.service.inherited_server(sock,handler) as server:
            thread=Thread(target=server.serve_forever,daemon=True)
            thread.start()
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    client.settimeout(3)
                    client.connect(str(path))
                    client.sendall(b'{"action":"invite","subject":"alice"}\n')
                    line=b""
                    while not line.endswith(b"\n"):
                        line += client.recv(1024)
                    response=json.loads(line)
                self.assertEqual(response["error"],"unauthorized_peer")
            finally:
                server.shutdown()


if __name__=="__main__":
    unittest.main()
