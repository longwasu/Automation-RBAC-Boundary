from typing import Dict, Any
from rbac_matrix import Matrix

import json
import os
import requests

def expected_allow(matrix: Matrix, role: str, group: str, method: str, action=None):
    admin_role = matrix.raw_data.get("adminRole")
    if role == admin_role:
        return True

    if method == 'GET':
        op = 'read' 
    else:
        op = 'write'

    if group == 'ar-command':
        if op == 'read':
            return True
                
        if action == 'delete':
            allowed_delete_roles = matrix.raw_data.get("ar", {}).get("taskDeleteRoles", [])
            return role in allowed_delete_roles
                
        action_risk = matrix.raw_data.get("ar", {}).get("actionRisk", {}).get(action)
            
        if action_risk:
            allowed_risks = matrix.raw_data.get("ar", {}).get("roleRisk", {}).get(role, [])
            if action_risk in allowed_risks:
                return True
                        
        return False

    grant = matrix.raw_data.get("baseline", {}).get(group, "")
    role_caps = matrix.raw_data.get("caps", {}).get(role, {})
    grant += role_caps.get(group, "")
            
    if op == 'read' and 'r' in grant:
        return True
    if op == 'write' and 'w' in grant:
        return True

    return False

def load_matrix(session = None):
    if session == None:
        with open('matrix.sample.json', 'r', encoding='utf-8') as f:
            print("Da load file sample 1")
            return Matrix(json.load(f))
    else:
        file_path = 'matrix.json'
        
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                print("Da load file json 2")
                return Matrix(json.load(f))
        
        else:
            try:
                api_url = "https://edr-dev.nstgroup.vn/api/role-tiers/matrix"
                response = session.session.get(api_url, timeout = 10)
                            
                if response.status_code == 200:
                    print("Da ket noi den server")
                    matrix_data = response.json()
                            
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(matrix_data, f, ensure_ascii=False, indent=4)
                    print("Da tao file json")

                print("Da load file json 3")                    
                return Matrix(matrix_data)
            
            except requests.exceptions.RequestException as e:
                print("Connection Error: khong tai duoc file Matrix.json")

if __name__ == "__main__":
    matrix: Matrix = load_matrix()

    test_cases = [
        # --- NHÓM 1: QUYỀN ADMIN (Bypass mọi thứ) ---
        ("all_access", "agents", "POST", None, True, "[Admin] Bỏ qua luật, cho phép ghi agents"),
        ("all_access", "ar-command", "POST", "run-command", True, "[Admin] Bỏ qua luật AR, chạy lệnh nguy hiểm"),

        # --- NHÓM 2: QUYỀN BASELINE (Quyền mặc định của mọi user) ---
        ("nst_soc_viewer", "health", "GET", None, True, "[Baseline] Viewer đọc health (r)"),
        ("nst_soc_viewer", "health", "POST", None, False, "[Baseline] Viewer ghi health (Chặn vì chỉ có r)"),
        ("nst_compliance_auditor", "self", "POST", None, True, "[Baseline] Auditor ghi profile cá nhân (rw)"),

        # --- NHÓM 3: QUYỀN CAPS (Quyền mở rộng theo Role) ---
        ("nst_soc_viewer", "agents", "GET", None, True, "[Caps] Viewer đọc agents (r)"),
        ("nst_soc_viewer", "agents", "POST", None, False, "[Caps] Viewer ghi agents (Chặn vì chỉ có r)"),
        ("nst_soc_manager", "agents", "POST", None, True, "[Caps] Manager ghi agents (rw)"),
        ("nst_compliance_auditor", "agents", "GET", None, False, "[Caps] Auditor đọc agents (Chặn vì caps trống)"),

        # --- NHÓM 4: ACTIVE RESPONSE - NHÓM LỆNH THƯỜNG ---
        ("nst_soc_viewer", "ar-command", "GET", None, True, "[AR] Ai cũng có quyền đọc danh sách AR (GET -> read)"),
        ("nst_soc_viewer", "ar-command", "POST", "ping", True, "[AR - Risk] Viewer chạy ping (Cho phép vì rủi ro low)"),
        ("nst_soc_viewer", "ar-command", "POST", "isolate", False, "[AR - Risk] Viewer chạy isolate (Chặn vì rủi ro high)"),
        ("nst_soc_analyst", "ar-command", "POST", "isolate", True, "[AR - Risk] Analyst chạy isolate (Cho phép vì có quyền high)"),
        ("nst_soc_analyst", "ar-command", "POST", "run-command", False, "[AR - Risk] Analyst chạy RCE (Chặn vì không có quyền exec)"),

        # --- NHÓM 5: ACTIVE RESPONSE - NHÓM XÓA TASK ---
        ("nst_soc_manager", "ar-command", "DELETE", "delete", True, "[AR - Delete] Manager xóa task (Có trong taskDeleteRoles)"),
        ("nst_soc_analyst", "ar-command", "DELETE", "delete", False, "[AR - Delete] Analyst xóa task (Chặn vì không có tên)"),
    ]

    print(f"{'KẾT QUẢ':<10} | {'MÔ TẢ KỊCH BẢN'}")
    print("-" * 75)

    passed_count = 0
    for role, group, method, action, expected, desc in test_cases:
        actual = expected_allow(matrix, role, group, method, action)
        
        if actual == expected:
            status = "PASS"
            passed_count += 1
        else:
            status = f"FAIL (Expected: {expected}, Actual: {actual})"
            
        print(f"{status:<10} | {desc}")
        
    print("-" * 75)
    print(f"Tổng kết: Đạt {passed_count}/{len(test_cases)} kịch bản kiểm thử.")