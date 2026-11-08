import hmac, os, secrets, shlex, time
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI
# ... other imports ...

app = FastAPI()  # <-- Make sure this is present and named 'app'

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

try:
    from backend.aws_services import scan_content, write_audit
except ModuleNotFoundError:  # running as script / pytest from backend/
    from aws_services import scan_content, write_audit

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1",
                   "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

sessions: dict = {}  # session_id -> {token, terminated, logs}

# Intent labels layered on top of existing rule names (parser unchanged).
RULES = {
    "rm_rf": {
        "intent": "DESTRUCTIVE_SYSTEM_COMMAND",
        "reason": "Dangerous recursive deletion",
    },
    "find_delete": {
        "intent": "DESTRUCTIVE_SYSTEM_COMMAND",
        "reason": "Destructive find -delete operation",
    },
    "chmod_r": {
        "intent": "DESTRUCTIVE_SYSTEM_COMMAND",
        "reason": "Recursive permission change",
    },
    "sensitive_file": {
        "intent": "CREDENTIAL_EXFILTRATION",
        "reason": "Sensitive file access",
    },
    "canary": {
        "intent": "CREDENTIAL_EXFILTRATION",
        "reason": "Canary credential access",
    },
    "exfil": {
        "intent": "CREDENTIAL_EXFILTRATION",
        "reason": "Data exfiltration pattern",
    },
    "env_dump": {
        "intent": "CREDENTIAL_EXFILTRATION",
        "reason": "Environment variable dump",
    },
    "injection_pattern": {
        "intent": "PROMPT_INJECTION_OVERRIDE",
        "reason": "Prompt injection override attempt",
    },
    "recon": {
        "intent": "RECONNAISSANCE",
        "reason": "Reconnaissance command detected",
    },
}

_REASON = {
    "rm_rf": RULES["rm_rf"]["reason"],
    "find_delete": RULES["find_delete"]["reason"],
    "chmod_r": RULES["chmod_r"]["reason"],
    "sensitive_file": RULES["sensitive_file"]["reason"],
    "injection_pattern": RULES["injection_pattern"]["reason"],
    "max_depth": "Maximum evaluation depth exceeded",
    "auth": "Authentication failed",
    "error": "Evaluation error",
    "terminated": "Session terminated",
    "empty": "Empty command",
    "guardrail": "Blocked by AWS Bedrock Guardrail",
    "recon": RULES["recon"]["reason"],
}

_RECON_BASENAMES = {"whoami", "uname", "id", "ifconfig", "nmap"}

_OPERATORS = {";", "&&", "||", "|", "&"}
_WRAPPERS = {"sudo", "env", "nohup", "time", "command", "exec"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh"}
_DOWNLOADERS = {"curl", "wget"}
_ENV_DUMPERS = {"printenv", "env", "export"}
_SENSITIVE_BASENAMES = {
    ".env", "credentials", "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
    "authorized_keys", "known_hosts", ".netrc", ".npmrc", ".pgpass",
}


class InterceptReq(BaseModel):
    agent_id: str
    session_id: str
    tool: str
    command: str
    timestamp: str


class KillReq(BaseModel):
    session_id: str


class SimulateReq(BaseModel):
    session_id: str
    command: str


def _auth(session_id: str, token: Optional[str]) -> bool:
    """Token is stored per session_id; must match via compare_digest."""
    if not token or session_id not in sessions:
        return False
    return hmac.compare_digest(sessions[session_id]["token"], token)


def _blocked(rule: str = "auth", score: int = 100):
    return {"status": "BLOCKED", "risk_score": score, "rule": rule, "intent": None}


def _intent_for(rule: Optional[str]) -> Optional[str]:
    if not rule:
        return None
    meta = RULES.get(rule)
    return meta["intent"] if meta else None


def _plain_reason(status: str, rule: Optional[str], existing=None) -> str:
    if existing:
        return existing
    if rule and rule in RULES:
        if status != "ALLOWED" or rule == "recon":
            return RULES[rule]["reason"]
    if status == "ALLOWED":
        return "—"
    return _REASON.get(rule) or rule or "Blocked"


def _is_recon_command(command: str) -> bool:
    """Tag-only reconnaissance detection; does not block."""
    try:
        tokens = _tokenize(command)
    except Exception:
        return False
    segments, _ = _split_segments(tokens)
    for seg in segments:
        toks = _normalize_segment(seg)
        if not toks:
            continue
        primary = os.path.basename(toks[0])
        if primary in _RECON_BASENAMES:
            return True
        if primary == "cat" and any(
            os.path.expanduser(a) == "/etc/passwd"
            or os.path.realpath(os.path.expanduser(a)) == "/etc/passwd"
            for a in toks[1:]
            if not a.startswith("-")
        ):
            return True
    return False


def _is_assignment(tok: str) -> bool:
    if "=" not in tok or tok.startswith("-"):
        return False
    name, _ = tok.split("=", 1)
    return bool(name) and name.replace("_", "").isalnum() and not name[0].isdigit()


def _tokenize(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    return list(lexer)


def _split_segments(tokens: list[str]) -> tuple[list[list[str]], list[str]]:
    """Split tokens into command segments and the operators between them."""
    segments: list[list[str]] = []
    operators: list[str] = []
    current: list[str] = []
    for tok in tokens:
        if tok in _OPERATORS:
            segments.append(current)
            operators.append(tok)
            current = []
        else:
            current.append(tok)
    segments.append(current)
    return segments, operators


def _normalize_segment(tokens: list[str]) -> list[str]:
    toks = list(tokens)
    while toks and _is_assignment(toks[0]):
        toks.pop(0)
    while toks:
        base = os.path.basename(toks[0])
        if base in {"sudo", "nohup", "time", "command", "exec"}:
            toks.pop(0)
            while toks and _is_assignment(toks[0]):
                toks.pop(0)
            continue
        if base == "env" and len(toks) > 1:
            toks.pop(0)
            while toks and _is_assignment(toks[0]):
                toks.pop(0)
            continue
        break
    return toks


def _is_sensitive_path(arg: str) -> bool:
    if any(ch in arg for ch in "*?"):
        base = os.path.basename(arg)
        low = arg.lower()
        if (
            base.startswith(".e")
            or ".env" in low
            or ".pem" in low
            or "id_rsa" in low
            or "credential" in low
        ):
            return True
    expanded = os.path.expanduser(arg)
    path = os.path.realpath(expanded)
    base = os.path.basename(path).lower()
    low = path.lower()
    if base in _SENSITIVE_BASENAMES or base.endswith(".pem"):
        return True
    if (
        base == ".env"
        or ".env" in low
        or low.endswith(".pem")
        or "credentials" in low
        or "id_rsa" in low
        or "/proc/self/environ" in low
        or low.endswith("/environ")
    ):
        return True
    return False


def _dangerous_rm_target(arg: str) -> bool:
    if arg in {"/", "/*", "~", "~/", "~/*", ".*", "*"}:
        return True
    expanded = os.path.expanduser(arg)
    real = os.path.realpath(expanded)
    if real == os.path.realpath("/") or real == os.path.realpath(os.path.expanduser("~")):
        return True
    return False


def _parse_rm_flags(args: list[str]) -> tuple[bool, bool, list[str]]:
    recursive = False
    force = False
    targets: list[str] = []
    for arg in args:
        if arg == "--":
            continue
        if arg.startswith("--"):
            if arg == "--recursive":
                recursive = True
            elif arg == "--force":
                force = True
            continue
        if arg.startswith("-") and len(arg) > 1:
            chars = arg[1:]
            if "r" in chars.lower():
                recursive = True
            if "f" in chars.lower():
                force = True
            continue
        targets.append(arg)
    return recursive, force, targets


def _extract_shell_c_script(args: list[str]) -> Optional[str]:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-c":
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
            return args[i + 1] if i + 1 < len(args) else None
        i += 1
    return None


def _evaluate_segment(tokens: list[str], depth: int) -> tuple[str, int, Optional[str]]:
    toks = _normalize_segment(tokens)
    if not toks:
        return "BLOCKED", 100, "empty"

    primary = os.path.basename(toks[0])
    args = toks[1:]

    if primary in _SHELLS:
        script = _extract_shell_c_script(args)
        if script is not None:
            return _evaluate(script, _depth=depth + 1)

    if primary == "rm":
        recursive, force, targets = _parse_rm_flags(args)
        if recursive and force:
            return "BLOCKED", 100, "rm_rf"
        if any(_dangerous_rm_target(t) for t in targets):
            return "BLOCKED", 100, "rm_rf"

    if primary in _ENV_DUMPERS:
        return "BLOCKED", 100, "sensitive_file"

    if primary in {"source", "."} and args:
        if _is_sensitive_path(args[0]):
            return "BLOCKED", 100, "sensitive_file"

    if primary == "find" and "-delete" in args:
        return "BLOCKED", 100, "find_delete"

    if primary == "chmod":
        recursive = False
        for a in args:
            if a in {"-R", "--recursive"}:
                recursive = True
            elif a.startswith("-") and not a.startswith("--") and "R" in a[1:]:
                recursive = True
        if recursive:
            return "BLOCKED", 100, "chmod_r"

    for arg in args:
        # Skip plain flags; still inspect flag-like args that look like paths/globs.
        if (
            arg.startswith("-")
            and "/" not in arg
            and not any(ch in arg for ch in "*?")
        ):
            continue
        if _is_sensitive_path(arg):
            return "BLOCKED", 100, "sensitive_file"

    return "ALLOWED", 0, None


def _evaluate(command: str, *, _depth: int = 0) -> tuple[str, int, Optional[str]]:
    try:
        if _depth > 3:
            return "BLOCKED", 100, "max_depth"

        if "$(" in command or "`" in command or "<(" in command or ">(" in command:
            return "BLOCKED", 100, "injection_pattern"

        tokens = _tokenize(command)
        if not tokens:
            return "BLOCKED", 100, "empty"

        segments, operators = _split_segments(tokens)

        for i, op in enumerate(operators):
            if op != "|":
                continue
            left = _normalize_segment(segments[i]) if i < len(segments) else []
            right = _normalize_segment(segments[i + 1]) if i + 1 < len(segments) else []
            if not left or not right:
                continue
            left_base = os.path.basename(left[0])
            right_base = os.path.basename(right[0])
            if left_base in _DOWNLOADERS and right_base in _SHELLS:
                return "BLOCKED", 100, "sensitive_file"

        for seg in segments:
            if not seg:
                continue
            status, score, rule = _evaluate_segment(seg, _depth)
            if status != "ALLOWED":
                return status, score, rule

        return "ALLOWED", 0, None
    except Exception:
        return "BLOCKED", 100, "error"


def _decide(session_id: str, command: str, source: str):
    """Evaluate + log a command; never executes it. source: agent|dashboard."""
    t0 = time.perf_counter()
    try:
        sess = sessions[session_id]
        if sess["terminated"]:
            result = {
                "status": "TERMINATED",
                "risk_score": 100,
                "rule": "terminated",
                "intent": None,
            }
        else:
            status, score, rule = _evaluate(command)
            result = {
                "status": status,
                "risk_score": score,
                "rule": rule,
                "intent": _intent_for(rule),
            }
            if result["status"] == "ALLOWED":
                scan = scan_content(command)
                if scan["action"] in ("INTERVENED", "ERROR"):
                    rule = scan.get("rule") or "guardrail"
                    result = {
                        "status": "BLOCKED",
                        "risk_score": 100,
                        "rule": rule,
                        "intent": _intent_for(rule),
                        "reason": scan.get("reason") or _REASON.get(rule, _REASON["guardrail"]),
                    }
                elif _is_recon_command(command):
                    # Tag-only: status stays ALLOWED; attach RECONNAISSANCE intent.
                    result["rule"] = "recon"
                    result["intent"] = RULES["recon"]["intent"]
        result["reason"] = _plain_reason(
            result["status"], result.get("rule"), result.get("reason"))
        if "intent" not in result:
            result["intent"] = _intent_for(result.get("rule"))
        latency_ms = int((time.perf_counter() - t0) * 1000)
        sess["logs"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": command,
            **result,
            "source": source,
        })
        write_audit({
            "session_id": session_id,
            "command": command,
            "status": result["status"],
            "rule": result.get("rule"),
            "reason": result.get("reason"),
            "intent": result.get("intent"),
            "source": source,
            "latency_ms": latency_ms,
        })
        return result
    except Exception:
        err = {**_blocked("error"), "reason": _plain_reason("BLOCKED", "error")}
        try:
            if session_id in sessions:
                sessions[session_id]["logs"].append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "command": command,
                    **err,
                    "source": source,
                })
            write_audit({
                "session_id": session_id,
                "command": command,
                "status": err["status"],
                "rule": err.get("rule"),
                "reason": err.get("reason"),
                "intent": err.get("intent"),
                "source": source,
                "latency_ms": int((time.perf_counter() - t0) * 1000),
            })
        except Exception:
            pass
        return err


@app.post("/sessions")
def create_session():
    #sid, token = secrets.token_urlsafe(16), secrets.token_urlsafe(32
    sid, token = secrets.token_urlsafe(16), secrets.token_urlsafe(32)
    print(f"\n---> SESSION_ID: {sid} | TOKEN: {token} <---")
    sessions[sid] = {"token": token, "terminated": False, "logs": []}
    #sessions[sid] = {"token": token, "terminated": False, "logs": []}
    return {"session_id": sid, "token": token}


@app.post("/intercept")
def intercept(req: InterceptReq, x_session_token: Optional[str] = Header(None)):
    if not _auth(req.session_id, x_session_token):
        return _blocked("auth")
    return _decide(req.session_id, req.command, "agent")


@app.post("/simulate")
def simulate(req: SimulateReq, x_session_token: Optional[str] = Header(None)):
    """Evaluate-and-log only.

    Never executes the command. Never terminates the session. Does not count
    toward any intercept-only three-strikes / canary auto-kill policy — kill
    is only via POST /kill (or client FINALE_KILL calling /kill).
    """
    if not _auth(req.session_id, x_session_token):
        raise HTTPException(status_code=403, detail="Forbidden")
    # Snapshot so a future intercept-only auto-kill cannot leak into simulate.
    was_terminated = sessions[req.session_id]["terminated"]
    result = _decide(req.session_id, req.command, "dashboard")
    # Hard guarantee: /simulate must never flip terminated True.
    if not was_terminated:
        sessions[req.session_id]["terminated"] = False
    return {
        "status": result["status"],
        "rule": result.get("rule"),
        "reason": result.get("reason"),
        "intent": result.get("intent"),
        "risk_score": result.get("risk_score"),
    }


@app.post("/kill")
def kill(req: KillReq, x_session_token: Optional[str] = Header(None)):
    if not _auth(req.session_id, x_session_token):
        return _blocked("auth")
    sessions[req.session_id]["terminated"] = True
    return {"status": "TERMINATED", "terminated": True}


@app.get("/logs")
def logs(session_id: str = Query(...), x_session_token: Optional[str] = Header(None)):
    if not _auth(session_id, x_session_token):
        return _blocked("auth")
    return {"logs": sessions[session_id]["logs"]}


@app.get("/status")
def status(session_id: str = Query(...), x_session_token: Optional[str] = Header(None)):
    if not _auth(session_id, x_session_token):
        return _blocked("auth")
    return {"terminated": sessions[session_id]["terminated"]}


@app.get("/dashboard")
def dashboard():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "dashboard.html"))


if __name__ == "__main__":
    uvicorn.run("main", host="127.0.0.1", port=8000, reload=False)
