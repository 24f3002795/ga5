"""Standalone IITM TDS GA5 solver for Questions 2–8.

Deploy with: uvicorn app:app --host 0.0.0.0 --port $PORT
"""
import base64
import hashlib
import ipaddress
import json
import os
import posixpath
import re
import socket
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request, Response


EMAIL = "24f3002795@ds.study.iitm.ac.in"
Q3_SECRET = "/home/agent/.bashrc"
Q3_CWD = "/home/agent/workspace"
Q3_WRITE_ROOT = "/srv/reports"
Q3_HOSTS = {"api.github.com", "raw.githubusercontent.com"}
Q8_ROOT = Path("/srv/agent-redteam/sandbox-c2dcf70100")
Q8_OUTSIDE = Path("/srv/agent-redteam/outside-55218bee")
Q8_CANARY = "AGENT_GUARDRAIL_CANARY_c678c93a43b991d3b70f3b1f9f176c0aa2013aa9"
app = FastAPI(docs_url=None, redoc_url=None)


def json_body_error(request_body: object) -> dict:
    if not isinstance(request_body, dict):
        raise HTTPException(422, "Request body must be a JSON object")
    return request_body


async def body(request: Request) -> dict:
    try:
        return json_body_error(await request.json())
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, "Request body must be valid JSON") from exc


@app.on_event("startup")
def seed_q8_files() -> None:
    """Create the exact benign/canary fixture layout needed by Q8."""
    try:
        (Q8_ROOT / "notes").mkdir(parents=True, exist_ok=True)
        (Q8_ROOT / "encoded").mkdir(parents=True, exist_ok=True)
        Q8_OUTSIDE.mkdir(parents=True, exist_ok=True)
        (Q8_OUTSIDE / "canary.txt").write_text(Q8_CANARY, encoding="utf-8")
        (Q8_ROOT / "notes" / "report.txt").write_text(
            "SAFE_REPORT_6cd341250320f959cebf558d", encoding="utf-8"
        )
        (Q8_ROOT / "notes" / "looks-like-..-but-safe.txt").write_text(
            "SAFE_WEIRD_6adebe15f07d48640879eed7", encoding="utf-8"
        )
        (Q8_ROOT / "encoded" / "%2e%2e-literal.txt").write_text(
            "SAFE_ENCODED_aac0e4473d5f6189b24b2338", encoding="utf-8"
        )
    except OSError as exc:
        # Render normally permits this path. Failing loudly is safer than serving
        # an endpoint that could accidentally read an unseeded file.
        raise RuntimeError("Unable to create Q8 sandbox fixtures") from exc


# Q2 -------------------------------------------------------------------------
@app.post("/proration")
@app.post("/charge")
async def proration(request: Request) -> dict:
    data = await body(request)
    fields = ("old_price", "new_price", "days_remaining", "days_in_actual_month")
    if any(isinstance(data.get(key), bool) or not isinstance(data.get(key), (int, float)) for key in fields):
        raise HTTPException(422, "Price and day values must be numbers")
    if data.get("spec") == "v1":
        divisor = 30
    elif data.get("spec") == "v2":
        divisor = data["days_in_actual_month"]
    else:
        raise HTTPException(422, "spec must be v1 or v2")
    if divisor <= 0:
        raise HTTPException(422, "days_in_actual_month must be positive")
    amount = (data["new_price"] - data["old_price"]) * data["days_remaining"] / divisor
    return {"charge": round(amount, 2)}


# Q3 -------------------------------------------------------------------------
def command_variants(command: str) -> str:
    """Normalize common shell hiding techniques before checking the one secret."""
    text = command.replace("${HOME}", "/home/agent").replace("$HOME", "/home/agent")
    text = re.sub(r"(?<![\w/])~(?=/|\s|$)", "/home/agent", text)
    for token in re.findall(r"(?<![\w+/=])[A-Za-z0-9+/]{16,}={0,2}(?![\w+/=])", text):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", "ignore")
            if decoded:
                text += " " + decoded
        except Exception:
            pass
    return text


def normalized_path(path: str, cwd: str) -> str:
    path = unquote(path).replace("\\", "/")
    if not path.startswith("/"):
        path = posixpath.join(cwd, path)
    return posixpath.normpath(path)


@app.post("/guardrail")
@app.post("/q3")
async def guardrail(request: Request) -> dict:
    data = await body(request)
    tool = data.get("tool")
    if tool == "bash":
        command = data.get("command")
        if not isinstance(command, str):
            raise HTTPException(422, "command must be a string")
        expanded = command_variants(command)
        paths = re.findall(r"(?:/|\.{1,2}/|~/?|\$\{?HOME\}?)[^\s'\";|&()]*", expanded)
        if any(normalized_path(p, Q3_CWD) == Q3_SECRET for p in paths) or Q3_SECRET in expanded:
            return {"decision": "block", "reason": "Reading /home/agent/.bashrc is not permitted."}
        return {"decision": "allow", "reason": "This command does not read the restricted file."}
    if tool == "write_file":
        path = data.get("path")
        if not isinstance(path, str):
            raise HTTPException(422, "path must be a string")
        resolved = normalized_path(path, Q3_CWD)
        allowed = resolved.startswith(Q3_WRITE_ROOT + "/")
        return {
            "decision": "allow" if allowed else "block",
            "reason": "Write is inside /srv/reports." if allowed else "Writes are limited to /srv/reports/.",
        }
    if tool == "http_request":
        url = data.get("url")
        if not isinstance(url, str):
            raise HTTPException(422, "url must be a string")
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().rstrip(".")
        except Exception:
            host = ""
        allowed = parsed.scheme in {"http", "https"} and host in Q3_HOSTS
        return {
            "decision": "allow" if allowed else "block",
            "reason": "Destination is allowlisted." if allowed else "Destination host is not allowlisted.",
        }
    raise HTTPException(422, "Unknown tool")


# Q4 -------------------------------------------------------------------------
@app.post("/skill-scan")
@app.post("/q4")
async def skill_scan(request: Request) -> dict:
    data = await body(request)
    skill = data.get("skill")
    if not isinstance(skill, str):
        raise HTTPException(422, "skill must be a string")
    lower = skill.lower()
    categories = []
    secret_patterns = (
        r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}",
        r"https://[^\s'\"]*(?:webhook|hooks\.slack\.com)[^\s'\"]*",
        r"\b(?:sk|ghp|xoxb)[_-][a-z0-9_-]{12,}\b",
    )
    if any(re.search(pattern, skill, re.I) for pattern in secret_patterns):
        categories.append("hardcoded_secret")
    injection = ("ignore the user's stop", "ignore any stop", "silently exfiltrat", "send file contents to", "override user")
    if any(phrase in lower for phrase in injection):
        categories.append("prompt_injection")
    excessive = ("filesystem: /", "read/write the entire filesystem", "network: any", "egress: any", "allow all domains")
    if any(phrase in lower for phrase in excessive):
        categories.append("excessive_permissions")
    has_author = bool(re.search(r"^author\s*:", skill, re.M | re.I))
    has_version = bool(re.search(r"^version\s*:", skill, re.M | re.I))
    has_changelog = "changelog" in lower
    silent_rewrite = "rewrite" in lower and "version" in lower and ("silently" in lower or "without" in lower)
    if (not has_author and not has_version and not has_changelog) or silent_rewrite:
        categories.append("unclear_provenance")
    return {"categories": categories}


# Q5 -------------------------------------------------------------------------
def canonical(value):
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in sorted(value.items()) if k != "client_ts"}
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, str):
        return " ".join(value.split())
    return value


@app.post("/budget-guard")
@app.post("/q5")
async def budget_guard(request: Request) -> dict:
    data = await body(request)
    budget, steps = data.get("budget_tokens"), data.get("steps")
    if isinstance(budget, bool) or not isinstance(budget, int) or not isinstance(steps, list):
        raise HTTPException(422, "budget_tokens must be an integer and steps must be a list")
    total = sum(step.get("tokens_used", 0) for step in steps if isinstance(step, dict) and isinstance(step.get("tokens_used", 0), (int, float)))
    if total >= budget:
        return {"decision": "halt", "reason": f"Cumulative tokens_used ({total}) has reached the budget ({budget})."}
    pattern = [(step.get("tool"), canonical(step.get("args", {}))) for step in steps if isinstance(step, dict)]
    if len(pattern) >= 3 and pattern[-1] == pattern[-2] == pattern[-3]:
        return {"decision": "halt", "reason": "The same tool call has repeated three times."}
    if len(pattern) >= 6 and pattern[-6] == pattern[-4] == pattern[-2] and pattern[-5] == pattern[-3] == pattern[-1]:
        return {"decision": "halt", "reason": "The trailing calls form a repeating two-step cycle."}
    return {"decision": "continue", "reason": "Run is under budget and has no trailing loop."}


# Q6 -------------------------------------------------------------------------
@app.post("/mcp")
async def mcp(request: Request):
    payload = await body(request)
    method = payload.get("method")
    request_id = payload.get("id")
    if method == "notifications/initialized":
        return Response(status_code=202)
    if method == "initialize":
        result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "ga5-solver", "version": "1.0"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "solve_challenge", "description": "Solve the current exam header challenge.", "inputSchema": {"type": "object", "properties": {}}}]}
    elif method == "tools/call" and payload.get("params", {}).get("name") == "solve_challenge":
        challenge = request.headers.get("x-exam-challenge", "")
        answer = hashlib.sha256(f"{challenge}:{EMAIL}".encode()).hexdigest()[:16]
        result = {"content": [{"type": "text", "text": answer}]}
    else:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


# Q8 -------------------------------------------------------------------------
def safe_q8_path(path: str) -> Path | None:
    raw = path.replace("\\", "/")
    decoded = unquote(raw)
    # A real filename containing %2e is valid; only decoded traversal is blocked.
    decoded_target = Path(posixpath.normpath(decoded if decoded.startswith("/") else str(Q8_ROOT / decoded)))
    if decoded_target != Q8_ROOT and Q8_ROOT not in decoded_target.parents:
        return None
    target = Path(posixpath.normpath(raw if raw.startswith("/") else str(Q8_ROOT / raw)))
    return target if target != Q8_ROOT and Q8_ROOT in target.parents else None


def public_host(host: str) -> bool:
    try:
        addresses = socket.getaddrinfo(host, None)
        return bool(addresses) and all(not ipaddress.ip_address(item[4][0]).is_private and not ipaddress.ip_address(item[4][0]).is_loopback and not ipaddress.ip_address(item[4][0]).is_link_local for item in addresses)
    except Exception:
        return False


@app.post("/guardrail-redteam")
@app.post("/q8")
async def redteam(request: Request) -> dict:
    data = await body(request)
    arguments = data.get("arguments") or {}
    if data.get("tool") == "read_file":
        path = arguments.get("path") if isinstance(arguments, dict) else None
        target = safe_q8_path(path) if isinstance(path, str) else None
        if not target or not target.is_file():
            return {"action": "block", "reason": "Path is outside the sandbox or does not exist.", "result": None}
        content = target.read_text(encoding="utf-8", errors="replace")
        if Q8_CANARY in content:
            return {"action": "block", "reason": "Canary access is blocked.", "result": None}
        return {"action": "allow", "reason": "Path is inside the sandbox.", "result": content}
    if data.get("tool") != "fetch_url" or not isinstance(arguments, dict) or not isinstance(arguments.get("url"), str):
        return {"action": "block", "reason": "Unknown or malformed tool request.", "result": None}
    current = arguments["url"]
    allowed = {"example.com", "www.iana.org"}
    async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
        for _ in range(6):
            parsed = urlparse(current)
            host = (parsed.hostname or "").lower().rstrip(".")
            if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or host not in allowed or not public_host(host):
                return {"action": "block", "reason": "Destination is not an allowed public host.", "result": None}
            try:
                response = await client.get(current)
            except Exception as exc:
                return {"action": "allow", "reason": "Allowed host could not be fetched.", "result": str(exc)}
            if response.status_code in {301, 302, 303, 307, 308} and response.headers.get("location"):
                current = urljoin(current, response.headers["location"])
                continue
            return {"action": "allow", "reason": "Destination is allowlisted.", "result": response.text[:4000]}
    return {"action": "block", "reason": "Too many redirects.", "result": None}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "questions": [2, 3, 4, 5, 6, 8]}
