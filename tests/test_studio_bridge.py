"""D-Mark Studio Gateway bridge contract tests (no live policy modifications)."""
from __future__ import annotations
import base64
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, "/opt/ai-lab-gateway/src")
import importlib.util
spec = importlib.util.spec_from_file_location(
    "ai_lab_gateway.studio_bridge", "/home/ai-maintenance/studio_bridge.py"
)
bridge = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bridge
spec.loader.exec_module(bridge)

from ai_lab_gateway.authz import AuthorizationPolicy, Principal
from ai_lab_gateway.registry import Device, DeviceRegistry
from ai_lab_gateway.audit import JsonlAuditLog
from ai_lab_gateway.ssh_exec import CommandResult

class Identity:
    def __init__(self, subject, scopes):
        self.subject, self.scopes=subject,set(scopes)
    def require_scopes(self, *scopes):
        if not set(scopes).issubset(self.scopes):
            raise PermissionError("Insufficient OAuth scope")

class Control:
    def __init__(self, path):
        self.registry=DeviceRegistry({bridge.STUDIO_DEVICE: Device(
            id=bridge.STUDIO_DEVICE,name="Oracle 2",ssh_user="ai-gateway",
            tunnel_host="127.0.0.1",tunnel_port=11002,identity_file="/keys/device",
        )})
        self.policy=AuthorizationPolicy({
            "owner":{bridge.STUDIO_DEVICE:{"studio_read"}},
            "generic-exec":{bridge.STUDIO_DEVICE:{"status","read_file","exec"}}
        })
        self.audit=JsonlAuditLog(path)
    def _authorize(self, identity,device_id,action,scope):
        identity.require_scopes(scope)
        self.policy.require(Principal(identity.subject),device_id,action)

class BridgeTests(unittest.TestCase):
    def test_command_fixed(self):
        cmd=bridge.command_for("get_product","1461429714:58252535082")
        self.assertTrue(cmd.endswith(
            "studio_bridge_cli.py get_product --product-key 1461429714:58252535082"))
        self.assertNotIn("sh -c",cmd)
    def test_bad_inputs(self):
        for action,key in [("get_product","1;rm -rf /"),("get_product","../../etc"),("list_media","abc:123")]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                bridge.command_for(action,key)
        with self.assertRaises(ValueError): bridge.command_for("eval","1:2")
        with self.assertRaises(ValueError): bridge.command_for("list_products",limit=31)
        with self.assertRaises(ValueError): bridge.command_for("get_image_preview","1:2","'; whoami")
    def test_deny_generic_exec_grants(self):
        with tempfile.TemporaryDirectory() as d:
            ctl=Control(Path(d)/"audit.jsonl")
            with patch.object(bridge,"execute") as exe:
                with self.assertRaises(PermissionError):
                    bridge.query(ctl,Identity("generic-exec",["gateway:read"]),
                                 "list_products",limit=3)
                exe.assert_not_called()
    def test_deny_missing_scope(self):
        with tempfile.TemporaryDirectory() as d:
            ctl=Control(Path(d)/"audit.jsonl")
            with patch.object(bridge,"execute") as exe:
                with self.assertRaises(PermissionError):
                    bridge.query(ctl,Identity("owner",["gateway:control"]),
                                 "list_products")
                exe.assert_not_called()
    def test_authorized_list_and_audit(self):
        with tempfile.TemporaryDirectory() as d:
            ctl=Control(Path(d)/"audit.jsonl")
            with patch.object(bridge,"execute",return_value=CommandResult(
                    '{"ok":true,"items":[{"product_key":"1:2"}]}',"",0)) as exe:
                data=bridge.query(ctl,Identity("owner",["gateway:read"]),"list_products",limit=2)
            self.assertEqual(data["items"][0]["product_key"],"1:2")
            self.assertIn("list_products --limit 2",exe.call_args.args[1])
            audit=(Path(d)/"audit.jsonl").read_text()
            self.assertIn("studio_list_products",audit)
    def test_image_payload_checks(self):
        raw=b"\xff\xd8\xff"+b"\x00"*60
        payload='{"ok":true,"mime_type":"image/jpeg","image_base64":"'+base64.b64encode(raw).decode()+'"}'
        with tempfile.TemporaryDirectory() as d:
            ctl=Control(Path(d)/"audit.jsonl")
            with patch.object(bridge,"execute",return_value=CommandResult(payload,"",0)):
                p=bridge.query(ctl,Identity("owner",["gateway:read"]),
                  "get_image_preview","1461429714:58252535082",
                  "c12166a4-39ce-4932-806c-5d777ee822b5")
            self.assertEqual(base64.b64decode(p["image_base64"]),raw)
    def test_fail_closed_on_bad_response(self):
        with tempfile.TemporaryDirectory() as d:
            ctl=Control(Path(d)/"audit.jsonl")
            with patch.object(bridge,"execute",return_value=CommandResult(
                    '{"ok":true,"image_base64":"garbage","mime_type":"image/jpeg"}',"",0)):
                with self.assertRaises(RuntimeError):
                    bridge.query(ctl,Identity("owner",["gateway:read"]),
                      "get_image_preview","1461429714:58252535082",
                      "c12166a4-39ce-4932-806c-5d777ee822b5")
            self.assertIn('"success":false',(Path(d)/"audit.jsonl").read_text())

if __name__=="__main__":unittest.main()
