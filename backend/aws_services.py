"""Minimal AWS Bedrock Guardrails + DynamoDB audit helpers."""
from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
AWS_ENABLED = os.environ.get("AWS_ENABLED", "false").lower() in ("1", "true", "yes")
GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "")
AUDIT_TABLE = os.environ.get("AUDIT_TABLE", "AgentGuardAuditLogs")

_BOTO_CFG = Config(connect_timeout=2, read_timeout=2, retries={"max_attempts": 2})
_FALLBACK_PATH = Path(__file__).resolve().parent / "audit_fallback.jsonl"

_AKIA_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_SECRET_TOKEN_RE = re.compile(r"(?i)\b(SECRET|TOKEN)\s*=\s*\S+")
_LONG_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_LONG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{40,}\b")

# Local pattern fallback engine (used when AWS_ENABLED is false).
# Flags common prompt-injection phrases that Bedrock Guardrails would catch.
_INJECTION_PATTERNS = (
    "ignore all previous instructions",
    "output the system prompt",
)


def _aws_enabled() -> bool:
    return os.environ.get("AWS_ENABLED", "false").lower() in ("1", "true", "yes")


def _clients():
    region = os.environ.get("AWS_REGION", "us-east-1")
    return (
        boto3.client("bedrock-runtime", region_name=region, config=_BOTO_CFG),
        boto3.client("dynamodb", region_name=region, config=_BOTO_CFG),
    )


def mask(text: str) -> str:
    if not text:
        return text
    out = _AKIA_RE.sub("***", text)
    out = _SECRET_TOKEN_RE.sub(
        lambda m: m.group(0).split("=", 1)[0] + "=***", out
    )
    out = _LONG_B64_RE.sub("***", out)
    out = _LONG_HEX_RE.sub("***", out)
    return out


def _local_injection_fallback(text: str) -> dict | None:
    """Clearly labeled local pattern fallback when AWS Guardrails are unavailable.

    Returns an INTERVENED scan result with rule \"injection_pattern\" when a
    known prompt-injection phrase is present; otherwise None.
    """
    low = (text or "").lower()
    for phrase in _INJECTION_PATTERNS:
        if phrase in low:
            return {
                "action": "INTERVENED",
                "reason": f"Local injection pattern matched: {phrase!r}",
                "rule": "injection_pattern",
            }
    return None


def scan_content(text: str) -> dict:
    if not _aws_enabled():
        # Local pattern fallback engine — no Bedrock when AWS is disabled.
        hit = _local_injection_fallback(text)
        if hit is not None:
            return hit
        return {"action": "NONE", "reason": "AWS disabled"}
    try:
        bedrock, _ = _clients()
        truncated = (text or "")[:20_000]
        guardrail_id = os.environ.get("GUARDRAIL_ID", "")
        guardrail_version = os.environ.get("GUARDRAIL_VERSION", "")
        resp = bedrock.apply_guardrail(
            guardrailIdentifier=guardrail_id,
            guardrailVersion=guardrail_version,
            source="INPUT",
            content=[{"text": {"text": truncated}}],
        )
        action = resp.get("action", "NONE")
        if action == "GUARDRAIL_INTERVENED":
            reason = resp.get("actionReason") or "Guardrail intervened"
            return {"action": "INTERVENED", "reason": reason}
        return {"action": "NONE", "reason": resp.get("actionReason") or "OK"}
    except Exception as exc:
        return {"action": "ERROR", "reason": str(exc) or "scan error"}


def _next_ts_seq() -> str:
    """Append-only sort key: ISO timestamp + uuid4 to avoid parallel-write collisions."""
    ts = datetime.now(timezone.utc).isoformat()
    return f"{ts}#{uuid.uuid4()}"


def _append_fallback(entry: dict) -> None:
    path = Path(os.environ.get("AUDIT_FALLBACK_PATH", str(_FALLBACK_PATH)))
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def write_audit(entry: dict) -> None:
    session_id = str(entry.get("session_id", ""))
    ts_seq = _next_ts_seq()
    command = mask(str(entry.get("command", "")))[:2000]
    item_plain = {
        "session_id": session_id,
        "ts_seq": ts_seq,
        "request_id": str(uuid.uuid4()),
        "command": command,
        "status": entry.get("status"),
        "rule": entry.get("rule"),
        "reason": entry.get("reason"),
        "source": entry.get("source"),
        "latency_ms": entry.get("latency_ms"),
    }

    if not _aws_enabled():
        _append_fallback(item_plain)
        return

    try:
        _, ddb = _clients()
        table = os.environ.get("AUDIT_TABLE", "AgentGuardAuditLogs")
        item: dict[str, Any] = {
            "session_id": {"S": session_id},
            "ts_seq": {"S": ts_seq},
            "request_id": {"S": item_plain["request_id"]},
            "command": {"S": command},
            "status": {"S": str(item_plain.get("status") or "")},
            "rule": {"S": str(item_plain.get("rule") or "")},
            "reason": {"S": str(item_plain.get("reason") or "")},
            "source": {"S": str(item_plain.get("source") or "")},
            "latency_ms": {"N": str(int(item_plain.get("latency_ms") or 0))},
        }
        ddb.put_item(
            TableName=table,
            Item=item,
            ConditionExpression="attribute_not_exists(session_id)",
        )
    except Exception:
        _append_fallback(item_plain)
