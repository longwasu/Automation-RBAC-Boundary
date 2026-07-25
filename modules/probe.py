from __future__ import annotations
import re
from modules.types import Probe, ProbeResult

REQUEST_PATH = "/api/request"
TIMEOUT = 15
HOST_ID_TOKEN = "{host_id}"
WRITE_VERB = {
    "agents": "DELETE",
    "ruleset": "PUT",
    "active-response": "PUT",
    "rbac": "POST",
    "groups": "POST",
    "agent-files": "DELETE",
    "agent-inventory": "PUT",
    "manager-admin": "PUT",
    "tasks": "DELETE",
    "self": "POST",
    "health": None,
    "agents-summary": None,
}
DEFAULT_WRITE_VERB = "POST"
MANDATORY_PROBES = {
    "rbac": [
        ("POST", "/security/users", {}),
        ("GET",  "/security/users", {}),
        ("POST", "/security/roles", {}),
    ],
}
RISK_ORDER = ["read", "change", "high", "exec"]
AR_PREFERRED = {"read": "ping", "change": "unisolate", "high": "isolate", "exec": "run-command"}

def generate_test_cases(matrix) -> list[ProbeResult]:
    """
    Chuyển đổi dữ liệu ma trận quyền (matrix) thành danh sách các kịch bản test (Probe).
    Duyệt qua từng group, sinh ra request GET. Nếu group cho phép ghi, sinh thêm request POST/PUT/DELETE. Gọi thêm xử lý riêng cho ar-command.
    """
    raw = getattr(matrix, "raw_data", matrix)
    probes = []
    seen = set()

    def _add(p):
        key = (p.group, p.method, p.path)
        if key not in seen:
            seen.add(key)
            probes.append(p)

    for entry in raw.get("groups", []) or []:
        group = entry.get("group")
        if not group:
            continue
        paths = _group_paths(group, entry.get("paths", ""))
        if group == "ar-command":
            for p in _ar_probes(paths, raw.get("ar", {}) or {}):
                _add(p)
        else:
            verb = WRITE_VERB.get(group, DEFAULT_WRITE_VERB)
            for path in paths:
                _add(Probe(group, "GET", path, {}))
                if verb:
                    _add(Probe(group, verb, path, {}))

    for group, entries in MANDATORY_PROBES.items():
        for method, path, body in entries:
            _add(Probe(group, method, path, body))

    return probes

def _group_paths(group, paths) -> list[str]:
    """Trích xuất mọi đường dẫn trong matrix liệt kê cho nhóm, chuyển thành chúng thành dạng gọi được."""
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

def _ar_probes(paths, ar) -> list[Probe]:
    """Probe cho ar-command: đọc mọi path, ghi trên path xoá task, dispatch theo mức rủi ro."""
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