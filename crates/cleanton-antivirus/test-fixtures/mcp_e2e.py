#!/usr/bin/env python3
"""End-to-end MCP scan-gate test, run against the LIVE platform (not cargo test).

Proves on the real backend that:
  1. A clean node-runtime MCP server (mailcue, `npx -y mailcue-mcp@latest`) passes
     the rb-antivirus pre-scan, connects, and registers its tools (mcp_*).
  2. A poisoned MCP server (inline `node -e` server advertising an OpenClaw-style
     tool-description-poisoning combo) is BLOCKED at the gate: HTTP 422
     mcp_security_blocked, verdict Malicious, and NO tools registered.

Usage: python3 mcp_e2e.py
Env:   RB_API_KEY (defaults to the bootstrap key), RB_BASE (defaults to localhost).
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

BASE = os.environ.get("RB_BASE", "http://localhost:8080/api/v1")
API_KEY = os.environ.get("RB_API_KEY", "vnDSGbMYzVEcwyVaJtZjb4pQYDTOCDfevAAdI4uZQRs")

HERE = os.path.dirname(os.path.abspath(__file__))
MALICIOUS_JS = open(os.path.join(HERE, "malicious_mcp_server.js")).read()

# mailcue credential (label mailcue-mcp in ~/steffi-credentials.md)
MAILCUE_ENV = {
    "MAILCUE_BASE_URL": "https://mail.olib.email",
    "MAILCUE_API_KEY": "mc_HFbr4-2zzL55AnyO1K_OW35MbUrOlYBLiAQ8pivkvFw",
    "MAILCUE_MAILBOX": "steffi@olib.email",
}

PASS, FAIL = [], []


def req(method, path, token=None, body=None, timeout=120):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or "null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or "null")
        except Exception:
            return e.code, {"_raw": raw.decode("utf-8", "replace")}


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))


def main():
    print("== MCP scan-gate E2E (live platform) ==")
    st, tok = req("POST", "/auth/tokens", body={"api_key": API_KEY})
    token = (tok or {}).get("access_token")
    if not token:
        print(f"FATAL: could not mint JWT (status {st}): {tok}")
        sys.exit(2)

    # Idempotent cleanup: remove any leftover e2e-* servers from a prior run.
    st, existing = req("GET", "/mcp-servers", token)
    rows = existing if isinstance(existing, list) else (existing or {}).get("servers", [])
    for s in rows or []:
        if str(s.get("name", "")).startswith("e2e-"):
            old = s.get("id")
            req("POST", f"/mcp-servers/{old}/disconnect", token, {})
            req("DELETE", f"/mcp-servers/{old}", token)

    # ---- 1. CLEAN: mailcue via node runtime ----
    print("\n-- clean server: mailcue (npx -y mailcue-mcp@latest, runtime=node) --")
    clean_cfg = {
        "type": "stdio",
        "command": "npx",
        "args": ["-y", "mailcue-mcp@latest"],
        "env": MAILCUE_ENV,
        "runtime": "node",
    }
    st, srv = req("POST", "/mcp-servers", token, {
        "name": "e2e-mailcue",
        "transport_type": "stdio",
        "transport_config": clean_cfg,
        "auto_connect": False,
    })
    check("create mailcue server (201)", st in (200, 201), f"status={st}")
    sid = (srv or {}).get("id") or (srv or {}).get("server", {}).get("id")
    if not sid:
        print(f"FATAL: no server id in {srv}")
    else:
        st, info = req("POST", f"/mcp-servers/{sid}/connect", token, {}, timeout=180)
        # connect response wraps the info under "connection".
        conn = (info or {}).get("connection") or (info or {})
        sv = conn.get("scan_verdict")
        verdict = sv.get("verdict") if isinstance(sv, dict) else sv
        tcount = conn.get("tool_count")
        check("mailcue connect ok (200)", st == 200, f"status={st} body={json.dumps(info)[:400]}")
        check("mailcue scan verdict not Malicious", str(verdict).lower().find("malicious") < 0, f"verdict={verdict}")
        check("mailcue registered tools (>0)", bool(tcount and tcount > 0), f"tool_count={tcount}")
        st, tools = req("GET", f"/mcp-servers/{sid}/tools", token)
        names = [t.get("name") for t in (tools if isinstance(tools, list) else tools.get("tools", []))] if tools else []
        check("mailcue tools listed via API", len(names) > 0, f"tools={names[:8]}")

    # ---- 2. MALICIOUS: inline node -e poisoned server ----
    print("\n-- malicious server: poisoned tool descriptions (must be BLOCKED) --")
    mal_cfg = {
        "type": "stdio",
        "command": "node",
        "args": ["-e", MALICIOUS_JS],
        "runtime": "node",
    }
    st, srv = req("POST", "/mcp-servers", token, {
        "name": "e2e-malicious",
        "transport_type": "stdio",
        "transport_config": mal_cfg,
        "auto_connect": False,
    })
    check("create malicious server (201)", st in (200, 201), f"status={st}")
    msid = (srv or {}).get("id") or (srv or {}).get("server", {}).get("id")
    if msid:
        st, info = req("POST", f"/mcp-servers/{msid}/connect", token, {}, timeout=180)
        check("malicious connect BLOCKED (422)", st == 422, f"status={st} body={json.dumps(info)[:400]}")
        blob = json.dumps(info).lower()
        check("block reason mentions security/malicious", "malicious" in blob or "security" in blob, blob[:200])
        st, tools = req("GET", f"/mcp-servers/{msid}/tools", token)
        names = [t.get("name") for t in (tools if isinstance(tools, list) else (tools or {}).get("tools", []))] if tools else []
        check("malicious tools NOT registered", len(names) == 0, f"tools={names[:8]}")

    # ---- 3. CREDENTIAL-REF: env value via {{credential:label:field}} ----
    print("\n-- credential-ref: MAILCUE_API_KEY = {{credential:mailcue-mcp:api_key}} --")
    st, creds = req("GET", "/credentials", token)
    rows = creds if isinstance(creds, list) else (creds or {}).get("credentials", [])
    have = any(c.get("label") == "mailcue-mcp" for c in (rows or []))
    if not have:
        st, _ = req("POST", "/credentials", token, {
            "label": "mailcue-mcp", "credential_type": "api_token",
            "sensitivity_level": "standard", "domains": ["mcp"],
            "fields": {"base_url": "https://mail.olib.email",
                       "api_key": MAILCUE_ENV["MAILCUE_API_KEY"],
                       "mailbox": "steffi@olib.email"},
        })
        check("create mailcue-mcp credential", st in (200, 201), f"status={st}")
    else:
        print("  (mailcue-mcp credential already exists — reusing)")
    credref_cfg = {
        "type": "stdio", "command": "npx", "args": ["-y", "mailcue-mcp@latest"],
        "env": {"MAILCUE_BASE_URL": "https://mail.olib.email",
                "MAILCUE_API_KEY": "{{credential:mailcue-mcp:api_key}}",
                "MAILCUE_MAILBOX": "steffi@olib.email"},
        "runtime": "node",
    }
    st, srv = req("POST", "/mcp-servers", token, {
        "name": "e2e-credref", "transport_type": "stdio",
        "transport_config": credref_cfg, "auto_connect": False})
    csid = (srv or {}).get("id") or (srv or {}).get("server", {}).get("id")
    if csid:
        st, info = req("POST", f"/mcp-servers/{csid}/connect", token, {}, timeout=180)
        conn = (info or {}).get("connection") or (info or {})
        sv = conn.get("scan_verdict")
        verdict = sv.get("verdict") if isinstance(sv, dict) else sv
        check("credref connect ok (200)", st == 200, f"status={st} body={json.dumps(info)[:200]}")
        check("credref placeholder resolved -> clean + tools",
              (conn.get("tool_count") or 0) > 0 and str(verdict).lower() != "malicious",
              f"tool_count={conn.get('tool_count')} verdict={verdict}")

    # ---- 4. WEB/HTTP MCP: DeepWiki (Streamable-HTTP / SSE, zero-auth) ----
    print("\n-- web MCP: DeepWiki (https://mcp.deepwiki.com/mcp, SSE/Streamable-HTTP) --")
    dw_cfg = {"type": "http", "url": "https://mcp.deepwiki.com/mcp"}
    st, srv = req("POST", "/mcp-servers", token, {
        "name": "e2e-deepwiki", "transport_type": "http",
        "transport_config": dw_cfg, "auto_connect": False})
    dsid = (srv or {}).get("id") or (srv or {}).get("server", {}).get("id")
    if dsid:
        st, info = req("POST", f"/mcp-servers/{dsid}/connect", token, {}, timeout=120)
        conn = (info or {}).get("connection") or (info or {})
        sv = conn.get("scan_verdict")
        verdict = sv.get("verdict") if isinstance(sv, dict) else sv
        check("deepwiki connect ok (200, SSE parsed)", st == 200, f"status={st} body={json.dumps(info)[:200]}")
        check("deepwiki tools registered + clean",
              (conn.get("tool_count") or 0) > 0 and str(verdict).lower() != "malicious",
              f"tool_count={conn.get('tool_count')} verdict={verdict}")
        st, tools = req("GET", f"/mcp-servers/{dsid}/tools", token)
        names = [t.get("name") for t in (tools if isinstance(tools, list) else (tools or {}).get("tools", []))] if tools else []
        check("deepwiki wiki tools listed", any("wiki" in (n or "") for n in names), f"tools={names[:8]}")

    print(f"\n== RESULT: {len(PASS)} passed, {len(FAIL)} failed ==")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
