from rbac_matrix import ProbeResult

import yaml

def load_invariants():
    with open("../invariants.yaml", 'r', encoding="UTF-8") as f:
        return yaml.safe_load(f)

def check_invariants(invariants_data, role, method, path):
    admin_role = invariants_data.get("admin_role")
    if role == admin_role:
        return "ALLOW"

    rules = invariants_data.get('rules', [])

    for rule in rules:
        methods = rule.get('methods', [])
        if method not in methods and "*" not in methods:
            continue

        paths = rule.get('paths', [])
        path_matched = any(path == p or str(path).startswith(f"{p}/") for p in paths)
        if not path_matched and "*" not in paths:
            continue

        target_roles = rule.get('roles', [])
        exclude_roles = rule.get('exclude_roles', [])

        is_target = ("*" in target_roles) or (role in target_roles)
        is_excluded = (role in exclude_roles)

        if is_target and not is_excluded:
            return rule.get('effect')

    return None

def reconcile(probe_result: ProbeResult):
    errors = []
    
    actual = probe_result.actual_allow
    expected = probe_result.matrix_expected
    verdict = probe_result.invariant_verdict
    
    if verdict == "DENY":
        
        if actual is True:
            errors.append("Error: Verdict != Actual")
            
        if expected is True:
            errors.append("Error: Verdict != Expected")
            
    if actual != expected:
        errors.append("Error: Actual != Expected")
        
    return errors

if __name__ == "__main__":
    invariants_data = load_invariants()
    test_cases = [
        # --- TEST TÍNH NĂNG ADMIN BYPASS ---
        ("all_access", "DELETE", "/security/core", "ALLOW", "[Admin] Xóa security (Bypass Rule 1)"),
        ("all_access", "POST", "/ar/run-command", "ALLOW", "[Admin] Chạy RCE (Bypass Rule 4)"),

        # --- RULE 1: Non-admin cấm ghi vào /security/* ---
        ("nst_soc_manager", "POST", "/security/config", "DENY", "[Rule 1] Manager ghi /security (Bị cấm)"),
        ("nst_soc_viewer", "DELETE", "/security/logs", "DENY", "[Rule 1] Viewer xóa /security (Bị cấm)"),
        ("nst_soc_manager", "GET", "/security/config", None, "[Rule 1] Manager ĐỌC /security (Thoát vì là GET)"),

        # --- RULE 2: viewer/auditor/hunter cấm ghi agents/ruleset/groups/AR ---
        ("nst_soc_viewer", "POST", "/agents", "DENY", "[Rule 2] Viewer tạo agents (Bị cấm)"),
        ("nst_threat_hunting_ro", "DELETE", "/ruleset", "DENY", "[Rule 2] Hunter xóa ruleset (Bị cấm)"),
        ("nst_soc_manager", "POST", "/agents", None, "[Rule 2] Manager tạo agents (Thoát vì không nằm trong list roles cấm)"),

        # --- RULE 3: auditor/hunter cấm GET /agents ---
        ("nst_compliance_auditor", "GET", "/agents", "DENY", "[Rule 3] Auditor đọc agents (Bị cấm)"),
        ("nst_soc_viewer", "GET", "/agents", None, "[Rule 3] Viewer đọc agents (Thoát vì Viewer không nằm trong rule này)"),

        # --- RULE 4: run-command = DENY trừ admin ---
        ("nst_soc_manager", "POST", "/ar/run-command", "DENY", "[Rule 4] Manager chạy run-command (Bị cấm)"),
        ("nst_soc_analyst", "POST", "/ar/run-command", "DENY", "[Rule 4] Analyst chạy run-command (Bị cấm)"),

        # --- RULE 5: AR high = DENY với viewer/auditor/hunter ---
        ("nst_soc_viewer", "POST", "/ar/isolate", "DENY", "[Rule 5] Viewer chạy isolate (Bị cấm)"),
        ("nst_threat_hunting_ro", "POST", "/ar/kill-process", "DENY", "[Rule 5] Hunter chạy kill-process (Bị cấm)"),
        ("nst_soc_analyst", "POST", "/ar/isolate", None, "[Rule 5] Analyst chạy isolate (Thoát vì không nằm trong list cấm)"),

        # --- TRƯỜNG HỢP SAFE (Không vướng luật thép nào) ---
        ("nst_soc_analyst", "GET", "/health", None, "[Safe] API an toàn"),
    ]

    print(f"{'KẾT QUẢ':<10} | {'MÔ TẢ KỊCH BẢN'}")
    print("-" * 80)

    passed_count = 0
    for role, method, path, expected, desc in test_cases:
        actual = check_invariants(invariants_data, role, method, path)
        
        if actual == expected:
            status = "PASS"
            passed_count += 1
        else:
            status = f"FAIL (Expected: {expected}, Actual: {actual})"
            
        print(f"{status:<10} | {desc}")
        
    print("-" * 80)
    print(f"Tổng kết: Đạt {passed_count}/{len(test_cases)} kịch bản kiểm thử.")