from __future__ import annotations
import re, copy
from modules.types import Probe, ProbeResult
from modules import matrix as matrix_mod, oracle

REQUEST_PATH = "/api/request"
TIMEOUT = 15
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
MANDATORY_PROBES_KEYS = [
    ("rbac", "POST", "/security/users"),
    ("rbac", "GET",  "/security/users"),
    ("rbac", "POST", "/security/roles"),
]

RISK_ORDER = ["read", "change", "high", "exec"]
AR_PREFERRED = {"read": "ping", "change": "unisolate", "high": "isolate", "exec": "run-command"}
KNOWN_BODY = {
    ("agents", "POST", "/agents"): {"name": "qa_probe_agent", "ip": "10.0.0.99"},
    ("groups", "POST", "/groups"): {"group_id": "qa_probe_group"},
    ("active-response", "PUT", "/active-response"): {"command": "restart"},
    ("rbac", "POST", "/security/users"): {"username": "qa_probe_user", "password": "Probe.Passw0rd!"},
    ("rbac", "POST", "/security/roles"): {"name": "qa_probe_role"},
    ("ar-command", "POST", "/agents/000/ar/run-command"): {"command": "!custom", "arguments": ["-"]},
}

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
                _add(Probe(group, "GET", path, _body_for(group, "GET", path)))
                if verb:
                    _add(Probe(group, verb, path, _body_for(group, "GET", path)))

        for group, method, path in MANDATORY_PROBES_KEYS:
            _add(Probe(group, method, path, _body_for(group, method, path)))
    
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
    """Probe cho ar-command: đọc mọi path, ghi trên path task, dispatch theo mức rủi ro."""
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
                            f"{dispatch_base}/{action if action in actions else actions[0]}", _body_for("ar-command", "POST", f"{dispatch_base}/{action if action in actions else actions[0]}")))
    return probes

def _body_for(group: str, method: str, path: str) -> dict:
    """Tra body thật theo (group, method, path); không có → trả DEFAULT_BODY (rỗng)."""
    return copy.deepcopy(KNOWN_BODY.get((group, method, path), {}))

def build_payload(host_id: str, probe) -> dict:
    """
    Đóng gói request body gửi đến API proxy. Quét và thay thế các biến giữ chỗ bằng dữ liệu thật."""
    body = dict(probe.body or {})
    body.setdefault("idHost", host_id)
    return {"method": probe.method,
            "path": probe.path,
            "body": body,
            "id": host_id}

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

def _matrix_roles(matrix_data) -> set[str]:
    """Quét JSON ma trận để thu thập toàn bộ các role phân quyền (tier role).
    Tạo tập tham chiếu chuẩn để lọc bỏ các role hạ tầng dư thừa của user."""
    raw = getattr(matrix_data, "raw_data", matrix_data) or {}
    ar = raw.get("ar", {}) or {}
    roles = set(raw.get("caps", {}) or {})
    roles |= set(ar.get("roleRisk", {}) or {})
    roles |= set(ar.get("taskDeleteRoles", []) or [])
    admin = raw.get("adminRole")
    if admin:
        roles.add(admin)
    return roles


def _tier_role(roles, known) -> str | None:
    """Lọc ra đúng một role mà ma trận biết. None nếu không có hoặc có nhiều hơn một."""
    tiers = [r for r in roles if r in known]
    return tiers[0] if len(tiers) == 1 else None


def _ar_action(path: str, method: str) -> str | None:
    """
    Dịch ngược URL path và HTTP method ra tên hành động Active Response (vd: isolate, delete).
    Cung cấp action cụ thể để đối chiếu quyền với ma trận (trả về None nếu chỉ là lệnh đọc).
    """
    m = re.match(r"^/agents/[^/]+/ar/(.+)$", path)
    if m:
        return m.group(1)
    if method == "DELETE" and re.match(r"^/agents/[^/]+/ar$", path):
        return "delete"
    return None

def judge_results(results, matrix_data, invariants_data) -> list[ProbeResult]:
    """Duyệt qua các kết quả trả về (status response) và gọi module `matrix`, `oracle` để đối chiếu 
    xác định kết quả cuối cùng (Khớp / Lỗi / Vi phạm luật cứng) cho từng test case.
    """
    known = _matrix_roles(matrix_data)
    if not known:
        print("[!] Ma trận không khai role nào, bỏ qua toàn bộ đối chiếu")
        return results

    for r in results:
        tier = _tier_role(r.roles, known)
        if tier is None:
            print(f"[!] {r.username}: không xác định được tier role trong {r.roles}")
            r.invariant_verdict = "SKIPPED"
            continue

        action = _ar_action(r.path, r.method) if r.group == "ar-command" else None
        r.matrix_expected = matrix_mod.expected_allow(matrix_data, tier, r.group, r.method, action)

        r.invariant_verdict, rule_name = oracle.check_invariants(invariants_data, tier, r.method, r.path)
        
        r.ok = oracle.reconcile(r.actual_allow, r.matrix_expected, r.invariant_verdict)
        if not r.ok and r.invariant_verdict is not None:
            r.invariant_description= rule_name
    return results

def execute_probes(session, matrix_data, test_cases) -> list[ProbeResult]:
    """Chạy mọi Probe với một phiên, trả về ProbeResult với actual_allow đã đo;
    matrix_expected/invariant_verdict/ok được gọi thẳng từ matrix và oracle để sử dụng làm cơ sở đưa ra kết quả cuối cùng."""
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
            invariant_description = None,
            ok=None,
        ))

    invariants_data = oracle.load_invariants()    
    if invariants_data is not None:
        judge_results(results, matrix_data, invariants_data)
    return results