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

def generate_test_cases(matrix) -> list[Probe]:
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

def build_payload(host_id: str, probe) -> dict:
    """
    Đóng gói request body gửi đến API proxy. Quét và thay thế các biến giữ chỗ bằng dữ liệu thật."""
    return {"method": probe.method,
            "path": probe.path,
            "body": _resolve_tokens(probe.body or {}, host_id),
            "id": host_id}

def _resolve_tokens(value, host_id):
    """Thay thế giá trị giả bằng dữ liệu thật được lấy về từ hệ thống."""
    if isinstance(value, str):
        return host_id if value == HOST_ID_TOKEN else value
    if isinstance(value, dict):
        return {k: _resolve_tokens(v, host_id) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_tokens(v, host_id) for v in value]
    return value

def run_probe(session, host_id: str, probe) -> int:
    """
    Thực thi kịch bản (Probe) lên server thật.
    Dùng Requests gửi HTTP POST lên proxy API kèm theo payload. Trả về mã trạng thái HTTP (status_code).
    """
    http = session.session
    base = getattr(http, "base_url", "")
    if not base:
        raise RuntimeError("session has no base_url (task-B must set http.base_url)")
    
    r = http.post(f"{base}{REQUEST_PATH}",
                    json=build_payload(host_id, probe), timeout=TIMEOUT)
    return r.status_code

def execute_probes(session, matrix_data, test_cases) -> list[ProbeResult]:
    """Chạy mọi Probe với một phiên, trả về ProbeResult với actual_allow đã đo;
    matrix_expected/invariant_verdict/ok để None cho task-C/task-E điền."""
    host_id = getattr(session.session, "api_id", None)
    if not host_id:
        raise RuntimeError("session không có api_id")

    results = []
    for probe in test_cases:
        try:
            status = run_probe(session, host_id, probe)
        except Exception as e:
            print(f"[!] {probe.method} {probe.path}: transport error: {e}")
            continue
        results.append(ProbeResult(
            username=session.username,
            roles=session.roles,
            group=probe.group,
            method=probe.method,
            path=probe.path,
            status=status,
            actual_allow=(status != 403),
            matrix_expected=None,
            invariant_verdict=None,
            ok=None,
        ))
    return results