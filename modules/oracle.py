from modules.types import ProbeResult
import yaml

def load_invariants():
    with open("invariants.yaml", 'r', encoding="UTF-8") as f:
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

def reconcile(probe_result: ProbeResult) -> ProbeResult:
    actual = probe_result.actual_allow
    expected = probe_result.matrix_expected
    verdict = probe_result.invariant_verdict

    probe_result.ok = True
    
    log_prefix = f"[{probe_result.method} {probe_result.path} | Role: {probe_result.roles}]"
    
    if verdict == "DENY":
        if actual is True:
            print(f"[!] FATAL ERROR {log_prefix}")
            probe_result.ok = False
            
        if expected is True:
            print(f"[!] CONFIG ERROR {log_prefix}")
            probe_result.ok = False
            
    elif verdict == "ALLOW":
        if actual is False:
            print(f"[!] FATAL ERROR {log_prefix}")
            probe_result.ok = False
            
        if expected is False:
            print(f"[!] CONFIG ERROR {log_prefix}")
            probe_result.ok = False
            
    if actual != expected:
        print(f"[!] LOGIC ERROR {log_prefix}")
        probe_result.ok = False
        
    return probe_result