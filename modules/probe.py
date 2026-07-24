from __future__ import annotations

import copy
import json
import os
import re
from typing import List, Optional

_shapes = None

def shapes():
    """
    Lấy các định nghĩa class (Session, Matrix, Probe...) từ rbac_matrix.py.
    Lấy Session/Matrix/Probe/ProbeResult từ rbac_matrix.py (import trễ, tránh vòng lặp).
    """
    global _shapes
    if _shapes is None:
        import rbac_matrix
        _shapes = rbac_matrix
    return _shapes


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
    "health": None,
    "agents-summary": None,
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

class ProbeError(RuntimeError):
    """Không lấy được mã trạng thái thật (lỗi truyền tải / thiếu base_url)."""

def generate_test_cases(matrix) -> List:
    """
    Chuyển đổi dữ liệu ma trận quyền (matrix) thành danh sách các kịch bản test (Probe).
    Duyệt qua từng group, sinh ra request GET. Nếu group cho phép ghi, sinh thêm request POST/PUT/DELETE. Gọi thêm xử lý riêng cho ar-command.
    """
    raw = getattr(matrix, "raw_data", matrix)
    Probe = shapes().Probe
    probes = []
    for entry in raw.get("groups", []) or []:
        group = entry.get("group")
        if not group:
            continue
        paths = _group_paths(group, entry.get("paths", ""))
        if group == "ar-command":
            probes += _ar_probes(paths, raw.get("ar", {}) or {})
        else:
            verb = WRITE_VERB.get(group, DEFAULT_WRITE_VERB)
            for path in paths:
                probes.append(Probe(group, "GET", path, _read_body(group, path)))
                if verb and path not in NO_WRITE_PROBE:
                    probes.append(Probe(group, verb, path, {}))
    return probes

def _group_paths(group, paths):
    """Trích xuất mọi đường dẫn trong matrix liệt kê cho nhóm, chuyển thành chúng thành dạng gọi được."""
    if group == "rbac":
        return ["/security/users"]
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
    """Body mặc định cho phép thử đọc (tham số phân trang nếu có)."""
    if path in READ_BODY_PATH:
        return copy.deepcopy(READ_BODY_PATH[path])
    if group in PAGINATED_GROUPS:
        return {"params": dict(LIST_PARAMS)}
    return {}

def _ar_probes(paths, ar):
    """Probe cho ar-command: đọc mọi path, ghi trên path xoá task, dispatch theo mức rủi ro."""
    Probe = shapes().Probe
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
    Đóng gói request body gửi đến API proxy. Quét và thay thế các biến giữ chỗ (như host_id) bằng dữ liệu thật."""
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
        raise ProbeError("session has no base_url (task-B must set http.base_url)")
    try:
        r = http.post(f"{base}{REQUEST_PATH}",
                      json=build_payload(host_id, probe), timeout=TIMEOUT)
    except Exception as e:
        raise ProbeError(f"{probe.method} {probe.path}: transport error: {e}")
    return r.status_code


def execute_probes(session, matrix_data, test_cases) -> List:
    """Chạy mọi Probe với một phiên, trả về ProbeResult với actual_allow đã đo;
    matrix_expected/invariant_verdict/ok để None cho task-C/task-E điền."""
    host_id = getattr(session.session, "api_id", None)
    if not host_id:
        raise ProbeError("session không có api_id")

    ProbeResult = shapes().ProbeResult
    results = []

    for probe in test_cases:
        try:
            status = run_probe(session, host_id, probe)
        except ProbeError as e:
            print(f"ProbeError: {e}")
            continue

        results.append(ProbeResult(
            username=session.username,
            roles=session.roles,
            group=probe.group,
            method=probe.method,
            path=probe.path,
            status=status,
            actual_allow=None,
            matrix_expected=None,
            invariant_verdict=None,
            ok=None,
        ))

    return results