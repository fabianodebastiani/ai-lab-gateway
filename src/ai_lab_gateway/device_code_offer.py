"""Validate public staging connection offers for the device-code workflow.

This module never modifies SSH configuration. Gateway-side approval and
controlled provisioner execution are external prerequisites.
"""
from __future__ import annotations

import base64
import hashlib
import json
from .enrollment import _validate_public_key

OFFER_VERSION = "ai-lab-ssh-offer-v1"
GATEWAY = "gateway.debasti.com"
FIELDS = frozenset({
    "version","request_id","device_id","access_mode","persistent",
    "gateway_host","gateway_ssh_port","gateway_tunnel_user",
    "gateway_ssh_host_key","gateway_management_public_key",
    "reverse_listen_host","reverse_listen_port","management_user",
    "device_tunnel_fingerprint","device_host_fingerprint"
})

def fingerprint(public: str) -> str:
    blob = base64.b64decode(_validate_public_key(public).split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")

def validate_offer(offer: object, *, request_id: str, device_id: str,
                   persistent: bool, tunnel_key: str, host_key: str) -> dict:
    if not isinstance(offer, dict) or frozenset(offer) != FIELDS:
        raise ValueError("unexpected connection offer fields")
    expected = {
        "version":OFFER_VERSION, "request_id":request_id,
        "device_id":device_id, "access_mode":"restricted",
        "persistent":persistent,"gateway_host":GATEWAY,
        "gateway_ssh_port":22,"gateway_tunnel_user":"tunnel",
        "reverse_listen_host":"127.0.0.1","management_user":"ai-gateway",
        "device_tunnel_fingerprint":fingerprint(tunnel_key),
        "device_host_fingerprint":fingerprint(host_key)
    }
    for k,v in expected.items():
        if type(offer[k]) is not type(v) or offer[k] != v:
            raise PermissionError("connection offer identity mismatch")
    port = offer["reverse_listen_port"]
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("invalid reverse port")
    for key in ("gateway_ssh_host_key","gateway_management_public_key"):
        normalized = _validate_public_key(offer[key])
        if offer[key] != normalized:
            raise ValueError("noncanonical Ed25519 public key")
    if offer["gateway_ssh_host_key"] == offer["gateway_management_public_key"]:
        raise PermissionError("gateway keys must be distinct")
    if len(json.dumps(offer,sort_keys=True)) > 4096:
        raise ValueError("oversized connection offer")
    return dict(offer)
