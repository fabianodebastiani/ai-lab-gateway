"""Static privilege-boundary tests for not-deployed ADR-029 MCP lookup."""
import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT/"src"/"ai_lab_gateway"/"server.py"
OPERATOR = ROOT/"src"/"ai_lab_gateway"/"device_code_operator.py"


class DeviceCodeMCPBoundaryTests(unittest.TestCase):
    def test_code_lookup_requires_explicit_feature_gate(self):
        tree=ast.parse(SERVER.read_text())
        feature_guard=[
            node for node in tree.body if isinstance(node,ast.If)
            and "AI_LAB_DEVICE_CODE_MCP_ENABLED" in ast.unparse(node.test)
        ]
        self.assertEqual(len(feature_guard),1)
        tools=[node for node in feature_guard[0].body
               if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))]
        self.assertEqual([node.name for node in tools],
                         ["pairing_lookup_code","pairing_confirm_code"])
        for tool in tools:
            code=ast.unparse(tool)
            self.assertIn("_authorize_device_pairing()",code)
            self.assertIn("identity.subject",code)
            self.assertNotIn("consent_verified",code)
            self.assertNotIn("activate(",code)

    def test_no_mcp_self_approval_endpoint(self):
        tree=ast.parse(SERVER.read_text())
        methods={node.name for node in ast.walk(tree)
                 if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
        for forbidden in ("pairing_confirm","pairing_approve",
                          "pairing_activate","device_code_approve"):
            self.assertNotIn(forbidden,methods)
        public=ast.parse(OPERATOR.read_text())
        allowed={node.value for node in ast.walk(public)
                 if isinstance(node,ast.Constant) and isinstance(node.value,str)}
        self.assertIn("lookup",allowed)
        self.assertIn("confirm",allowed)
        self.assertNotIn("consent_verified",allowed)


if __name__=="__main__":
    unittest.main()
