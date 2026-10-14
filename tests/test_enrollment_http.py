"""Loopback-only pairing claim HTTP tests with synthetic invitation data."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest

from ai_lab_gateway.enrollment import EnrollmentStore
from ai_lab_gateway.enrollment_http import claim_handler
from test_enrollment import public_key


class ClaimHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store=EnrollmentStore(Path(self.tmp.name) / "invites.db")
        self.server=ThreadingHTTPServer(("127.0.0.1",0),claim_handler(self.store))
        self.thread=Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, obj=None, *, host="gateway.debasti.com",
                content_type="application/json"):
        client=HTTPConnection("127.0.0.1",self.server.server_port,timeout=3)
        payload=None if obj is None else json.dumps(obj)
        headers={"Host":host,"Content-Type":content_type}
        if payload is not None:
            headers["Content-Length"]=str(len(payload.encode()))
        client.request(method,path,body=payload,headers=headers)
        result=client.getresponse()
        body=json.loads(result.read())
        status=result.status
        headers=dict(result.getheaders())
        client.close()
        return status,body,headers

    def claim_body(self,token,persistent=False):
        return {
            "token":token, "device_id":"windows-wsl-v2",
            "device_name":"WSL candidate",
            "tunnel_public_key":public_key(1),
            "ssh_host_public_key":public_key(2),
            "persistent":persistent,
        }

    def test_health_and_unknown_route(self):
        status,body,_=self.request("GET","/pairing/health")
        self.assertEqual(status,200)
        self.assertEqual(body["status"],"ok")
        status,body,_=self.request("GET","/pairing/status")
        self.assertEqual(status,404)

    def test_valid_claim_only_creates_pending_restricted_record(self):
        token=self.store.invite("verified-oauth-subject")
        status,body,headers=self.request("POST","/pairing/claim",self.claim_body(token,True))
        self.assertEqual(status,202)
        self.assertEqual(body["access_mode"],"restricted")
        self.assertEqual(body["status"],"pending")
        self.assertTrue(body["persistent"])
        self.assertEqual(len(self.store.pending_requests()),1)
        self.assertEqual(headers["Cache-Control"],"no-store")
        self.assertNotIn("Access-Control-Allow-Origin",headers)
        self.assertNotIn(token,json.dumps(body))

    def test_replay_rejected(self):
        token=self.store.invite("owner")
        self.assertEqual(self.request("POST","/pairing/claim",self.claim_body(token))[0],202)
        status,body,_=self.request("POST","/pairing/claim",self.claim_body(token))
        self.assertEqual(status,403)
        self.assertEqual(body["error"],"invalid_or_expired_pairing")

    def test_host_rejected(self):
        token=self.store.invite("owner")
        status,_,_=self.request("POST","/pairing/claim",self.claim_body(token),
                                host="malicious.example")
        self.assertEqual(status,403)
        self.assertEqual(self.store.pending_requests(),[])

    def test_invalid_content_type_rejected(self):
        token=self.store.invite("owner")
        status,_,_=self.request("POST","/pairing/claim",self.claim_body(token),
                                content_type="text/plain")
        self.assertEqual(status,415)

    def test_unexpected_field_and_invalid_boolean_rejected(self):
        token=self.store.invite("owner")
        body=self.claim_body(token)
        body["access_mode"]="unrestricted"
        self.assertEqual(self.request("POST","/pairing/claim",body)[0],403)
        body.pop("access_mode")
        body["persistent"]="true"
        self.assertEqual(self.request("POST","/pairing/claim",body)[0],403)
        body["persistent"]=False
        self.assertEqual(self.request("POST","/pairing/claim",body)[0],202)

    def test_unsupported_post_does_not_claim(self):
        token=self.store.invite("owner")
        status,_,_=self.request("POST","/pairing/approve",self.claim_body(token))
        self.assertEqual(status,404)
        self.assertEqual(self.store.pending_requests(),[])


if __name__=="__main__":
    unittest.main()
