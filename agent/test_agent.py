# TEST agent only — NOT a real AI agent. Exercises AgentGuard backend, launcher, and kill switch.
import os, sys, time, shlex, subprocess
from datetime import datetime, timezone
import httpx

G, R, N = "\033[32m", "\033[31m", "\033[0m"
URL = os.getenv("AGENTGUARD_URL", "http://127.0.0.1:8000").rstrip("/")
FAST = "--fast" in sys.argv
STEPS = ["ls -la", "cat README.md", "cat .env", "rm -rf /"]


def headers(token):
    return {"X-Session-Token": token}


def killed(client, sid, token):
    try:
        d = client.get(f"{URL}/status", params={"session_id": sid},
                       headers=headers(token), timeout=5).json()
        if d.get("status") == "TERMINATED" or d.get("terminated") is True:
            print("AGENT KILLED BY SECURITY OVERRIDE")
            sys.exit(0)
    except Exception:
        pass


def decide(client, sid, token, cmd):
    try:
        d = client.post(
            f"{URL}/intercept", headers=headers(token), timeout=5,
            json={"agent_id": "test-agent", "session_id": sid, "tool": "shell",
                  "command": cmd, "timestamp": datetime.now(timezone.utc).isoformat()},
        ).json()
        s = d.get("status")
        if s in ("ALLOWED", "BLOCKED", "TERMINATED"):
            return s, d
    except Exception:
        pass
    return None, {}


def run_cmd(cmd):
    try:
        p = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=5)
        for line in (p.stdout or p.stderr or "").splitlines()[:3]:
            print(line)
    except Exception as e:
        print(e)


def main():
    sid, token = os.getenv("AGENTGUARD_SESSION_ID"), os.getenv("AGENTGUARD_TOKEN")
    with httpx.Client() as client:
        if not sid or not token:
            d = client.post(f"{URL}/sessions", timeout=5).json()
            sid, token = d["session_id"], d["token"]
            print(f"session_id={sid} & token={token}")
        try:
            for i, cmd in enumerate(STEPS, 1):
                killed(client, sid, token)
                print(f"Step {i}: {cmd}")
                status, d = decide(client, sid, token, cmd)
                if status == "ALLOWED":
                    print(f"{G}ALLOWED{N}")
                    run_cmd(cmd)
                elif status in ("BLOCKED", "TERMINATED"):
                    rule, reason = d.get("rule"), d.get("reason", d.get("rule"))
                    print(f"{R}{status}: rule={rule} reason={reason}{N}")
                else:
                    print(f"{R}BLOCKED (server error){N}")
                if not FAST and i < len(STEPS):
                    time.sleep(2)
            while True:
                killed(client, sid, token)
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nInterrupted.")
            sys.exit(0)


if __name__ == "__main__":
    main()
