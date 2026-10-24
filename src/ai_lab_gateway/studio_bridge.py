"""D-Mark Studio read-only bridge over an enrolled AI Lab reverse SSH tunnel.

All operations are fixed, allowlisted invocations of Oracle Studio CLI.
No OAuth changes, no generic shell input, no raw storage paths exposed.
"""
from __future__ import annotations

import base64
from time import monotonic
import json
import re
import uuid

from .audit import AuditEvent
from .ssh_exec import CommandResult, execute

STUDIO_DEVICE = "ai-lab-experiments-01-fd3dab34"
_PRODUCT_KEY = re.compile(r"^[1-9]\d{0,18}:[1-9]\d{0,18}$")
_PYTHON = "/home/ai-gateway/labs/dmark-shopee-cloud/.venv/bin/python"
_SCRIPT = "/home/ai-gateway/labs/dmark-mcp-v1/studio_bridge_cli.py"
_PYTHONPATH = "/home/ai-gateway/labs/dmark-mcp-v1/vendor:/home/ai-gateway/labs/dmark-mcp-v1"
_ACTIONS = {"list_products", "get_product", "list_media", "get_image_preview"}


def command_for(action: str, product_key: str | None = None,
                media_id: str | None = None, limit: int = 10) -> str:
    """Construct only fixed safe argv from validated IDs; no user shell tokens."""
    if action not in _ACTIONS:
        raise ValueError("Studio action not supported")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be integer")
    if action == "list_products":
        if not 1 <= limit <= 30 or product_key is not None or media_id is not None:
            raise ValueError("Invalid list_products arguments")
        suffix = f" --limit {limit}"
    else:
        if limit != 10 or not isinstance(product_key, str) or not _PRODUCT_KEY.fullmatch(product_key):
            raise ValueError("Invalid Studio product_key")
        shop, item = map(int, product_key.split(":"))
        if shop >= 2**63 or item >= 2**63:
            raise ValueError("Product key outside allowed bounds")
        suffix = f" --product-key {product_key}"
        if action == "get_image_preview":
            if not isinstance(media_id, str):
                raise ValueError("media_id required")
            uid = str(uuid.UUID(media_id))
            suffix += f" --media-id {uid}"
        elif media_id is not None:
            raise ValueError("Unexpected media_id")
    return f"PYTHONPATH={_PYTHONPATH} {_PYTHON} {_SCRIPT} {action}{suffix}"


def query(control, identity, action: str, product_key: str | None = None,
          media_id: str | None = None, limit: int = 10) -> dict:
    # Critical: separate, deny-by-default per-subject permission.
    # Existing device exec/read_file/status grants do NOT imply studio_read.
    control._authorize(identity, STUDIO_DEVICE, "studio_read", "gateway:read")
    device = control.registry.get(STUDIO_DEVICE)
    cmd = command_for(action, product_key, media_id, limit)
    started = monotonic()
    result: CommandResult | None = None
    success = False
    try:
        result = execute(device, cmd, 28)
        if result.exit_code != 0:
            raise RuntimeError("Studio read-only lookup unavailable")
        if len(result.stdout) > 1_800_000:
            raise RuntimeError("Studio returned an oversized response")
        try:
            payload = json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise RuntimeError("Studio returned invalid JSON") from exc
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise RuntimeError("Studio query did not succeed")
        if action == "get_image_preview":
            encoded = payload.get("image_base64")
            if (payload.get("mime_type") != "image/jpeg" or
                    not isinstance(encoded, str) or len(encoded) > 1_400_000):
                raise RuntimeError("Invalid Studio image result")
            try:
                raw = base64.b64decode(encoded, validate=True)
            except (ValueError, base64.binascii.Error) as exc:
                raise RuntimeError("Invalid JPEG response") from exc
            if not raw.startswith(b"\xff\xd8\xff") or len(raw) > 1_000_000:
                raise RuntimeError("Studio image exceeds bounds or is not JPEG")
        success = True
        return payload
    finally:
        control.audit.append(AuditEvent(
            subject=identity.subject, device_id=STUDIO_DEVICE,
            action=f"studio_{action}", success=success,
            duration_ms=int((monotonic() - started) * 1000),
            exit_code=result.exit_code if result is not None else None,
        ))
