import json

def load_matrix(session):
    if session == None:
        with open('../matrix.sample.json', 'r', encoding='utf-8') as f:
            return json.load(f)

def expected_allow(matrix, roles, group, method, action=None):
    admin_role = matrix.get("adminRole", "all_access")
    if admin_role in roles:
        return True

    if method == 'GET':
        op = 'read' 
    else:
        op = 'write'

    if group == 'ar-command':
        if op == 'read':
            return True
            
        if action == 'delete':
            allowed_delete_roles = matrix.get("ar", {}).get("taskDeleteRoles", [])
            return any(role in allowed_delete_roles for role in roles)
            
        action_risk = matrix.get("ar", {}).get("actionRisk", {}).get(action)
        
        if action_risk:
            for role in roles:
                allowed_risks = matrix.get("ar", {}).get("roleRisk", {}).get(role, [])
                if action_risk in allowed_risks:
                    return True
                    
        return False

    grant = matrix.get("baseline", {}).get(group, "")
    for role in roles:
        role_caps = matrix.get("caps", {}).get(role, {})
        grant += role_caps.get(group, "")
        
    if op == 'read' and 'r' in grant:
        return True
    if op == 'write' and 'w' in grant:
        return True

    return False

if __name__ == "__main__":
    matrix_data = load_matrix()
    
    # Danh sách 15 kịch bản để bao phủ toàn bộ các góc ngách của ma trận quyền[cite: 1, 2]
    # Cấu trúc: (roles, group, method, action, expected_result, mô_tả)
    test_cases = [
        # 1. Admin bypass toàn bộ
        (["all_access"], "rbac", "POST", None, True, "Admin ghi rbac (Bypass)"),
        
        # 2. Quyền mặc định (Baseline)
        (["nst_threat_hunting_ro"], "health", "GET", None, True, "Hunter đọc health (từ baseline)"),
        (["nst_compliance_auditor"], "self", "POST", None, True, "Auditor ghi self (từ baseline)"),
        
        # 3. Quyền mở rộng (Caps) thông thường
        (["nst_soc_viewer"], "agents", "GET", None, True, "Viewer đọc agents"),
        (["nst_soc_viewer"], "agents", "POST", None, False, "Viewer ghi agents (Chặn)"),
        (["nst_soc_manager"], "agents", "POST", None, True, "Manager ghi agents"),
        (["nst_compliance_auditor"], "agents", "GET", None, False, "Auditor đọc agents (Không có trong caps)"),
        
        # 4. Quyền trên Active Response (ar-command)
        (["nst_soc_viewer"], "ar-command", "GET", None, True, "Viewer xem danh sách AR"),
        (["nst_soc_viewer"], "ar-command", "POST", "ping", True, "Viewer chạy ping (rủi ro read)"),
        (["nst_soc_viewer"], "ar-command", "POST", "isolate", False, "Viewer chạy isolate (Chặn do rủi ro high)"),
        (["nst_soc_analyst"], "ar-command", "POST", "isolate", True, "Analyst chạy isolate (rủi ro high)"),
        
        # 5. Quyền xóa task AR (taskDeleteRoles)
        (["nst_soc_analyst"], "ar-command", "DELETE", "delete", False, "Analyst xóa task AR (Chặn)"),
        (["nst_soc_manager"], "ar-command", "DELETE", "delete", True, "Manager xóa task AR"),
        
        # 6. Quyền RCE (Run-command)
        (["nst_soc_manager"], "ar-command", "POST", "run-command", False, "Manager chạy RCE (Chặn do rủi ro exec)"),
        (["all_access"], "ar-command", "POST", "run-command", True, "Admin chạy RCE (Bypass)"),
    ]

    print(f"{'KẾT QUẢ':<10} | {'MÔ TẢ KỊCH BẢN'}")
    print("-" * 65)

    passed_count = 0
    for roles, group, method, action, expected, desc in test_cases:
        actual = expected_allow(matrix_data, roles, group, method, action)
        if actual == expected:
            status = "PASS"
            passed_count += 1
        else:
            status = f"FAIL"
            
        print(f"{status:<10} | {desc}")
        
    print("-" * 65)
    print(f"Tổng kết: Đạt {passed_count}/{len(test_cases)} kịch bản kiểm thử.")