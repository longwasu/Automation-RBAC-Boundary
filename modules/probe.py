"""task-D — probe catalog & executor.

    build_probes(matrix) -> list[Probe]         # from matrix.groups + matrix.ar
    run_probe(session, host_id, probe) -> int   # POST /api/request -> HTTP status
CLI:
    python probe.py --list                        # the catalog
    python probe.py --dry-run                     # the payloads it would send
    python probe.py --run --user NAME             # python probe.py --run --config config.yaml --matrix fixtures/matrix.sample.json --user demo_soc_manager
    python probe.py --run --all-users             # every tier, low -> high
"""
from __future__ import annotations
import copy
import json
import re
import sys

import requests
from common.types import Probe, Session
REQUEST_PATH = "/api/request"
TIMEOUT = 15
HOST_ID_TOKEN = "{host_id}"
ID_PLACEHOLDER = "<api-id>"
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
    "self": "POST",
    "health": None,             # read-only
    "agents-summary": None,     # read-only
}
DEFAULT_WRITE_VERB = "POST"
LIST_PARAMS = {"offset": 0, "limit": 10}
READ_BODY_PATH = {
    "/agents": {"params": {"q": "id!=000", "offset": 0, "limit": 10, "sort": "+id"}},
    "/rules": {"params": {"offset": 0, "limit": 10, "sort": "+id"}},
    "/decoders": {"params": {"offset": 0, "limit": 10, "sort": "+filename"}},
}
PAGINATED_GROUPS = {"agent-inventory", "agent-files", "groups", "tasks", "rbac", "ruleset"}
NO_WRITE_PROBE = {"/security/user/authenticate"}

EXTRA_PROBES = {
    "self": [
        ("GET", "/security/users/me/policies", {"idHost": HOST_ID_TOKEN}),
    ],
}
RISK_ORDER = ["read", "change", "high", "exec"]
AR_PREFERRED = {"read": "ping", "change": "unisolate", "high": "isolate", "exec": "run-command"}
DENY_STATUS = 403
INVALID_STATUSES = (401,)
class ProbeError(RuntimeError):
    """No real HTTP status could be obtained (transport error / no base_url)."""

def build_probes(matrix) -> list:
    probes = []
    for entry in matrix.get("groups", []) or []:
        group = entry.get("group")
        if not group:
            continue
        paths = _group_paths(group, entry.get("paths", ""))
        if group == "ar-command":
            probes += _ar_probes(paths, matrix.get("ar", {}) or {})
        else:
            verb = WRITE_VERB.get(group, DEFAULT_WRITE_VERB)
            for path in paths:
                probes.append(Probe(group, "GET", path, _read_body(group, path)))
                if verb and path not in NO_WRITE_PROBE:
                    probes.append(Probe(group, verb, path, {}))
        probes += _extra_probes(group)
    return probes

def _group_paths(group, paths):
    """EVERY path the matrix lists for the group, made concrete."""
    if group == "rbac":
        return ["/security/users"]              # /security/* is a wildcard
    out = []
    for raw in (paths or "").split(","):
        path = raw.strip()
        if not path:
            continue
        path = re.sub(r"\{[^}]+\}", "000", path)
        path = re.sub(r"\[[^\]]*\]", "", path)
        if path.endswith("/*"):
            path = path[:-2] or "/"
        out.append(path)
    return out or [f"/{group}"]

def _read_body(group, path):
    if path in READ_BODY_PATH:
        return copy.deepcopy(READ_BODY_PATH[path])
    if group in PAGINATED_GROUPS:
        return {"params": dict(LIST_PARAMS)}
    return {}

def _extra_probes(group):
    return [Probe(group, method, path, copy.deepcopy(body))
            for method, path, body in EXTRA_PROBES.get(group, ())]

def _ar_probes(paths, ar):
    probes, dispatch_base = [], None
    for path in paths:
        probes.append(Probe("ar-command", "GET", path, {}))
        if re.match(r"^/agents/[^/]+/ar$", path):
            dispatch_base = path
            probes.append(Probe("ar-command", "DELETE", path, {}))
    if not dispatch_base:
        return probes

    by_risk = {}
    for action, risk in (ar.get("actionRisk", {}) or {}).items():
        by_risk.setdefault(risk, []).append(action)
    known = [r for r in RISK_ORDER if r in by_risk]
    for risk in known + [r for r in by_risk if r not in RISK_ORDER]:
        actions = by_risk[risk]
        action = AR_PREFERRED.get(risk)
        probes.append(Probe("ar-command", "POST",
                            f"{dispatch_base}/{action if action in actions else actions[0]}", {}))
    return probes

def build_payload(host_id: str, probe: Probe) -> dict:
    return {"method": probe.method,
            "path": probe.path,
            "body": _resolve_tokens(probe.body or {}, host_id),
            "id": host_id}

def _resolve_tokens(value, host_id):
    if isinstance(value, str):
        return host_id if value == HOST_ID_TOKEN else value
    if isinstance(value, dict):
        return {k: _resolve_tokens(v, host_id) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_tokens(v, host_id) for v in value]
    return value


def run_probe(session: Session, host_id: str, probe: Probe) -> int:
    base = getattr(session.http, "base_url", "")
    if not base:
        raise ProbeError("session has no base_url (task-B must set http.base_url)")
    try:
        r = session.http.post(f"{base}{REQUEST_PATH}",
                              json=build_payload(host_id, probe), timeout=TIMEOUT)
    except requests.RequestException as e:
        raise ProbeError(f"{probe.method} {probe.path}: transport error: {e}") from e
    return r.status_code


def classify_status(status: int) -> str:
    if status == DENY_STATUS:
        return "deny"
    if status in INVALID_STATUSES:
        return "invalid"
    return "allow"
# ===== CLI ====================================================================
def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="task-D probe catalog / executor")
    ap.add_argument("--list", action="store_true", help="print the catalog")
    ap.add_argument("--dry-run", action="store_true", help="print the payloads")
    ap.add_argument("--run", action="store_true", help="fire at a live dashboard")
    target = ap.add_mutually_exclusive_group()
    target.add_argument("--user", metavar="NAME", help="probe ONE tier")
    target.add_argument("--all-users", action="store_true", help="probe every tier")
    ap.add_argument("--id-user", metavar="NAME",
                    help="account used to read /hosts/apis (default: highest tier)")
    ap.add_argument("--matrix", default="fixtures/matrix.sample.json")
    ap.add_argument("--config", default="config.yaml")
    a = ap.parse_args()
    if a.run:
        if not a.user and not a.all_users:
            ap.error("--run needs a target: --user NAME or --all-users")
        return _run_live(a.config, a.user, a.all_users, a.matrix, a.id_user)
    with open(a.matrix, encoding="utf-8") as f:
        probes = build_probes(json.load(f))
    if a.dry_run:
        for p in probes:
            print(json.dumps(build_payload(ID_PLACEHOLDER, p), ensure_ascii=False))
    else:
        print(f"{len(probes)} probes:")
        for p in probes:
            print(f"  {p.group:16} {p.method:6} {p.path}")
    return 0


def _bootstrap(cfg, id_user):
    import auth
    users = cfg.users_low_to_high()
    if id_user:
        candidates = [u for u in users if u.username == id_user]
        if not candidates:
            raise SystemExit(f"--id-user {id_user!r} not in config")
    else:
        candidates = list(reversed(users))          # highest tier first
    last = None
    for u in candidates:
        try:
            s = auth.login(cfg.base_url, u.username, u.password, cfg.verify_tls,
                           roles=(u.roles or None))
            return s.username, auth.get_manager_host_id(s)
        except auth.AuthError as e:
            last = e
    raise SystemExit(f"no usable bootstrap account: {last}")


def _run_live(config_path, user, all_users, matrix_path, id_user):
    import auth
    from common.config import load_config

    cfg = load_config(config_path)
    targets = cfg.users_low_to_high() if all_users else \
        [u for u in cfg.users_low_to_high() if u.username == user]
    if not targets:
        raise SystemExit(f"user {user!r} not in config")

    with open(matrix_path, encoding="utf-8") as f:
        matrix = json.load(f)
    probes = build_probes(matrix)

    boot_user, host_id = _bootstrap(cfg, id_user)
    print(f"[bootstrap] account={boot_user} id={host_id}")
    print(f"[catalog]   {matrix_path}: {len(matrix.get('groups', []))} groups "
          f"-> {len(probes)} probes | {len(targets)} tier(s)")

    invalid = 0
    for u in targets:
        print(f"\n== {u.username} ==")
        try:
            s = auth.login(cfg.base_url, u.username, u.password, cfg.verify_tls,
                           roles=(u.roles or None))
        except auth.AuthError as e:
            print(f"  LOGIN FAILED: {e}")
            continue
        if auth.prepare_session(s, host_id) is None:
            print("  WARNING: no nst-token; /api/request may 401")
        for p in probes:
            try:
                status = run_probe(s, host_id, p)
            except ProbeError as e:
                print(f"  {p.method:6} {p.path:34} -> ERROR {e}")
                continue
            verdict = classify_status(status)
            invalid += verdict == "invalid"
            print(f"  {p.method:6} {p.path:34} -> {status} {verdict}")

    if invalid:
        print(f"\n[WARN] {invalid} probe(s) returned 401 — those requests never reached a "
              f"policy decision and are NOT allows.", file=sys.stderr)
        return 1
    return 0
if __name__ == "__main__":
    sys.exit(_cli())