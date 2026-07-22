import json

def load_matrix(session=None):
    with open('matrix.sample.json', 'r', encoding='utf-8') as f:
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
            allowed_delete_roles = matrix.get("ar", {}).get("taskDeleteRoles", []) #
            return any(role in allowed_delete_roles for role in roles)
            
        action_risk = matrix.get("ar", {}).get("actionRisk", {}).get(action)
        
        if action_risk:
            for role in roles:
                allowed_risks = matrix.get("ar", {}).get("roleRisk", {}).get(role, []) #[cite: 2]
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
    
    print("--- Test nhóm thông thường ---")
    print("Test 1 (Viewer ghi agents - Kỳ vọng False):", expected_allow(matrix_data, ["nst_soc_viewer"], "agents", "POST"))
    print("Test 2 (Manager ghi agents - Kỳ vọng True):", expected_allow(matrix_data, ["nst_soc_manager"], "agents", "POST"))
    
    print("\n--- Test nhóm Active Response ---")
    # Test 3: Viewer chạy lệnh ping (rủi ro 'read') -> Được phép[cite: 2]
    print("Test 3 (Viewer chạy ping - Kỳ vọng True):", expected_allow(matrix_data, ["nst_soc_viewer"], "ar-command", "POST", action="ping"))
    
    # Test 4: Viewer chạy lệnh isolate (rủi ro 'high') -> Bị chặn[cite: 2]
    print("Test 4 (Viewer chạy isolate - Kỳ vọng False):", expected_allow(matrix_data, ["nst_soc_viewer"], "ar-command", "POST", action="isolate"))
    
    # Test 5: Analyst chạy lệnh isolate (rủi ro 'high') -> Được phép[cite: 2]
    print("Test 5 (Analyst chạy isolate - Kỳ vọng True):", expected_allow(matrix_data, ["nst_soc_analyst"], "ar-command", "POST", action="isolate"))
    
    # Test 6: Analyst chạy lệnh run-command (rủi ro 'exec') -> Bị chặn (Chỉ admin mới được)[cite: 2]
    print("Test 6 (Analyst chạy run-command - Kỳ vọng False):", expected_allow(matrix_data, ["nst_soc_analyst"], "ar-command", "POST", action="run-command"))