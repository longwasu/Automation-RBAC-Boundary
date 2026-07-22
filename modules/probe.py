"""task-D — probe catalog & executor.
CLI:
    python probe.py --list                        # the catalog
    python probe.py --dry-run                     # show the payloads it would send
    python probe.py --run --user NAME             # python modules.probe.py --run --config config.yaml --user demo_soc_viewer
    python probe.py --run --all-users             # every tier, low -> high
"""
from __future__ import annotations
import copy
import os
import re
import sys
import requests
from common.types import Probe, Session

REQUEST_PATH = "/api/request"
TIMEOUT = 15
WRITE_VERB = {
    "agents": "DELETE",
    "ruleset": "PUT",
    "active-response": "PUT",
    "rbac": "POST",
    "groups": "POST",
    "agent-files": "POST",
    "agent-inventory": "PUT",
    "manager-admin": "PUT",
    "tasks": "DELETE",
    "self": "PUT",
    "health": None,
    "agents-summary": None,
}
DEFAULT_WRITE_VERB = "POST"
LIST_PARAMS = {"offset": 0, "limit": 10, "sort": "+id"}
SAFE_LIST_PARAMS = {"offset": 0, "limit": 10}
READ_BODY = {
    "agents": {"params": {"q": "id!=000", **LIST_PARAMS}},
    "ruleset": {"params": LIST_PARAMS},
    "agents-summary": {},
    "agent-inventory": {"params": SAFE_LIST_PARAMS},
    "agent-files": {"params": SAFE_LIST_PARAMS},
    "groups": {"params": SAFE_LIST_PARAMS},
    "tasks": {"params": SAFE_LIST_PARAMS},
    "rbac": {"params": SAFE_LIST_PARAMS},
}
KNOWN_RISK_ORDER = ["read", "change", "high", "exec"]
_AR_PREFERRED = {"read": "ping", "change": "unisolate", "high": "isolate", "exec": "run-command"}

class ProbeError(RuntimeError):
    """run_probe could not obtain a real HTTP status (transport error / no base_url)."""

# ===== build_probes (offline) =================================================
def build_probes(matrix) -> list:
    probes: list = []
    ar = matrix.get("ar", {}) or {}
    for entry in _iter_groups(matrix):
        group = entry["group"]
        if not group:
            continue
        if group == "ar-command":
            probes.extend(_ar_probes(ar))
            continue
        rep = _rep_path(group, entry.get("paths", ""))
        if rep is None:
            continue
        probes.append(Probe(group=group, method="GET", path=rep, body=_read_body(group)))
        verb = WRITE_VERB.get(group, DEFAULT_WRITE_VERB)
        if verb:
            probes.append(Probe(group=group, method=verb, path=rep, body={}))
    return probes

def _read_body(group):
    return copy.deepcopy(READ_BODY.get(group, {}))

def _iter_groups(matrix):
    out = []
    for g in matrix.get("groups", []) or []:
        if isinstance(g, dict):
            out.append({"group": g.get("group"), "paths": g.get("paths", "")})
        elif isinstance(g, str):
            out.append({"group": g, "paths": ""})
    return out

def _rep_path(group, paths):
    if group == "rbac":
        return "/security/users"
    first = paths.split(",")[0].strip() if paths else ""
    if not first:
        first = "/" + group
    first = first.replace("{id}", "000")
    first = re.sub(r"\[[^\]]*\]", "", first)
    if first.endswith("/*"):
        first = first[:-2] or "/"
    return first

def _ar_probes(ar):
    probes = [Probe(group="ar-command", method="GET", path="/ar", body={})]
    action_risk = ar.get("actionRisk", {}) or {}
    by_risk = {}
    for action, risk in action_risk.items():
        by_risk.setdefault(risk, []).append(action)
    order = [r for r in KNOWN_RISK_ORDER if r in by_risk] + \
            [r for r in by_risk if r not in KNOWN_RISK_ORDER]
    for risk in order:
        actions = by_risk[risk]
        action = _AR_PREFERRED.get(risk)
        if action not in actions:
            action = actions[0]
        probes.append(Probe(group="ar-command", method="POST",
                            path=f"/agents/000/ar/{action}", body={}))
    return probes

# ===== run_probe (live) =======================================================
def build_payload(host_id: str, probe: Probe) -> dict:
    """The /api/request envelope. Key order matches the dashboard's own calls."""
    return {"method": probe.method, "path": probe.path,
            "body": probe.body or {}, "id": host_id}

def run_probe(session: Session, host_id: str, probe: Probe) -> int:
    if os.environ.get("RBAC_AUTH_STUB") == "1":
        return _stub_status(session, probe)

    base = getattr(session.http, "base_url", "")
    if not base:
        raise ProbeError("session has no base_url (task-B must set http.base_url)")
    try:
        r = session.http.post(f"{base}{REQUEST_PATH}",
                              json=build_payload(host_id, probe), timeout=TIMEOUT)
    except requests.RequestException as e:
        raise ProbeError(f"{probe.method} {probe.path}: transport error: {e}") from e
    return r.status_code

def _stub_status(session, probe):
    from common.matrix import _toy_allow
    allow = _toy_allow(session.roles, probe)
    if os.environ.get("RBAC_STUB_INJECT_FAULT") == "1":
        if ("nst_soc_viewer" in session.roles
                and probe.group == "agents"
                and probe.method.upper() != "GET"):
            allow = True
    return 200 if allow else 403

# ===== self-test CLI ==========================================================
def _cli():
    import argparse
    import json
    ap = argparse.ArgumentParser(description="task-D probe catalog / executor")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print /api/request payloads")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--matrix", default="matrix.sample.json")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--user", default=None)
    a = ap.parse_args()

    if a.run:
        return _run_live(a.config, a.user, a.matrix)

    with open(a.matrix, encoding="utf-8") as f:
        probes = build_probes(json.load(f))
    if a.dry_run:
        for p in probes:
            print(json.dumps(build_payload("<api id>", p), ensure_ascii=False))
    else:
        print(f"{len(probes)} probes:")
        for p in probes:
            print(f"  {p.group:16} {p.method:6} {p.path}")
    return 0

def _run_live(config_path, user, matrix_path):
    import json
    import auth
    from common.config import load_config
    cfg = load_config(config_path)
    with open(matrix_path, encoding="utf-8") as f:
        probes = build_probes(json.load(f))
    users = cfg.users_low_to_high()
    if user:
        users = [u for u in users if u.username == user]
        if not users:
            print(f"user {user!r} not in config")
            return 2
    for u in users:
        s = auth.login(cfg.base_url, u.username, u.password, cfg.verify_tls,
                       roles=(u.roles or None))
        host_id = auth.get_manager_host_id(s)
        print(f"== {u.username} (id={host_id}) ==")
        for p in probes:
            try:
                st = run_probe(s, host_id, p)
                print(f"  {p.method:6} {p.path:34} -> {st} {'deny' if st == 403 else 'allow'}")
            except ProbeError as e:
                print(f"  {p.method:6} {p.path:34} -> ERROR {e}")
    return 0
if __name__ == "__main__":
    sys.exit(_cli())