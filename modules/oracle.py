from modules.types import ProbeResult
import yaml

def load_invariants():
    with open("invariants.yaml", 'r', encoding="UTF-8") as f:
        return yaml.safe_load(f)

def check_invariants(invariants_data, role, method, path):
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
            effect = rule.get('effect')
            rule_name = rule.get('descriptions')

            return effect, rule_name

    return None, None

def reconcile(actual: bool, expected: bool, verdict: str) -> bool:
    if verdict == "DENY":
        if actual is True:
            return False
            
        if expected is True:
            return False
            
    elif verdict == "ALLOW":
        if actual is False:
            return False
            
        if expected is False:
            return False
            
    if actual != expected:
        return False

    return True