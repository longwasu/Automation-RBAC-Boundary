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
            return Matrix(json.load(f))
    else:
        file_path = 'matrix.json'
        
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return Matrix(json.load(f))
        
        else:
            try:
                api_url = "https://edr-dev.nstgroup.vn/api/role-tiers/matrix"
                response = session.session.get(api_url, timeout = 10)
                            
                if response.status_code == 200:
                    matrix_data = response.json()
                            
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(matrix_data, f, ensure_ascii=False, indent=4)
               
                return Matrix(matrix_data)
            
            except requests.exceptions.RequestException as e:
                print("Connection Error: khong tai duoc file Matrix.json")