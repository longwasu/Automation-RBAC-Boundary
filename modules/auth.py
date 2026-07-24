from __future__ import annotations
import os
import sys
from typing import List
import requests
import yaml

_shapes = None
def shapes():
    global _shapes
    if _shapes is None:
        import rbac_matrix
        _shapes = rbac_matrix
    return _shapes

LOGIN_PATH = "/auth/login"
HOSTS_APIS_PATH = "/hosts/apis"
API_LOGIN_PATH = "/api/login"
AUTHINFO_PATH = "/api/v1/auth/authinfo"
CHROME_VERSION = "149"
BROWSER_HEADERS = {
    "osd-xsrf": "kibana", #cân nhắc đổi thành true
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
}
SESSION_COOKIE = "security_authentication"
NST_USER_COOKIE = "nst-user"
NST_API_COOKIE = "nst-api"
NST_TOKEN_COOKIE = "nst-token"
TOKEN_KEYS = ("nst_token", "nstToken", "token", "jwt", "access_token")

TIMEOUT = 15

class AuthError(RuntimeError):
    """Không dựng được một phiên dùng được."""

def _warn(msg):
    print(f"[auth] {msg}", file=sys.stderr)


def _unwrap(data):
    return data.get("data", data) if isinstance(data, dict) else data
def _new_http(base, verify_tls):
    http = requests.Session()
    http.verify = verify_tls
    http.headers.update(BROWSER_HEADERS)
    http.headers["Origin"] = base           # same-origin: chỉ biết khi có base,
    http.headers["Referer"] = f"{base}/"    # nên đặt ở đây chứ không ở hằng số
    http.base_url = base
    if not verify_tls:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return http

def set_nst_cookies(http, username=None, api_id=None, token=None):
    if username:
        http.cookies.set(NST_USER_COOKIE, username)
    if api_id:
        http.cookies.set(NST_API_COOKIE, api_id)
    if token:
        http.cookies.set(NST_TOKEN_COOKIE, token)


def login(base_url, username, password, verify_tls=False, roles=None) :
    base = base_url.rstrip("/")
    http = _new_http(base, verify_tls)
    try:
        resp = http.post(f"{base}{LOGIN_PATH}",
                         json={"username": username, "password": password},
                         timeout=TIMEOUT)
    except requests.RequestException as e:
        raise AuthError(f"{username}: cannot reach {base}{LOGIN_PATH}: {e}") from e

    if resp.status_code in (401, 403):
        raise AuthError(f"{username}: rejected (HTTP {resp.status_code}) — bad credentials")
    if resp.status_code >= 400:
        raise AuthError(f"{username}: login failed (HTTP {resp.status_code})")
    if SESSION_COOKIE not in http.cookies:
        raise AuthError(f"{username}: HTTP {resp.status_code} but no {SESSION_COOKIE!r} cookie")

    set_nst_cookies(http, username=username)
    return shapes().Session(session=http, username=username,
                            roles=roles if roles is not None else _fetch_roles(http, base))

def get_manager_host_id(session) -> str:
    http = session.session
    base = getattr(http, "base_url", "")
    if not base:
        raise AuthError("session has no base_url (login must set http.base_url)")
    try:
        r = http.get(f"{base}{HOSTS_APIS_PATH}", timeout=TIMEOUT)
        r.raise_for_status()
        api_id = _extract_api_id(r.json())
    except (requests.RequestException, ValueError) as e:
        raise AuthError(f"{HOSTS_APIS_PATH} failed: {e}") from e
    if not api_id:
        raise AuthError(f"{HOSTS_APIS_PATH} returned no api id")
    set_nst_cookies(http, api_id=api_id)
    http.api_id = api_id                # task-D đọc lại từ đây
    return api_id

def fetch_nst_token(session, api_id, force=False):
    http = session.session
    base = getattr(http, "base_url", "")
    try:
        r = http.post(f"{base}{API_LOGIN_PATH}",
                      json={"idHost": api_id, "force": bool(force)}, timeout=TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as e:
        _warn(f"{API_LOGIN_PATH} (idHost={api_id!r}) hỏng: {e}")
        return None

    token = http.cookies.get(NST_TOKEN_COOKIE) or _extract_token(r)
    if not token:
        _warn(f"{API_LOGIN_PATH} (idHost={api_id!r}) -> HTTP {r.status_code} nhưng không có "
              f"{NST_TOKEN_COOKIE}: {_describe_body(r)}. "
              f"Đã tìm Set-Cookie và các khoá {TOKEN_KEYS}. "
              f"Thêm tên khoá thật vào TOKEN_KEYS trong modules/auth.py.")
        return None
    set_nst_cookies(http, token=token)
    return token

def _describe_body(resp):
    try:
        data = resp.json()
    except ValueError:
        text = (resp.text or "").strip()
        return f"body không phải JSON ({len(text)} byte)" if text else "body rỗng"
    if isinstance(data, dict):
        inner = data.get("data")
        shape = f"keys={sorted(data)}"
        if isinstance(inner, dict):
            shape += f", data.keys={sorted(inner)}"
        return shape
    return f"body là {type(data).__name__}"

def login_all_users(config_path: str) -> List:
    base_url, verify_tls, users = _read_config(config_path)
    if not users:
        print(f"[ERR] {config_path}: không có tài khoản nào trong mục users")
        return []
    sessions = []
    api_id = None
    for user in users:
        try:
            s = login(base_url, user["username"], user["password"], verify_tls)
        except AuthError as e:
            print(f"[ERR] {e}")
            continue

        if api_id is None:                  # lấy một lần, ở tài khoản đầu tiên vào được
            try:
                api_id = get_manager_host_id(s)
            except AuthError as e:
                print(f'[ERR] {user["username"]}: không đọc được api id: {e}')
                continue
        else:
            set_nst_cookies(s.session, api_id=api_id)
            s.session.api_id = api_id

        if fetch_nst_token(s, api_id) is None:
            print(f'[ERR] {user["username"]}: không có nst-token, /api/request sẽ trả 401')

        print(f"[OK]  {user["username"]:24} id={api_id}")
        print(f"      config={user["roles"]} server={s.roles or '(không lấy được)'}")
        sessions.append(s)
    return sessions

def _read_config(path: str):
    with open(_resolve_config(path), "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    system = raw.get("system") or {}
    users = [{"username": u["username"],
              "password": u.get("password", ""),
              "roles": [u["role"]] if u.get("role") else []}
             for u in raw.get("test_users", [])]
    return system["base_url"], bool(system.get("verify_tls", False)), users
def _resolve_config(path: str) -> str:
    if os.path.exists(path):
        return path
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, os.path.basename(path))
    if os.path.exists(candidate):
        return candidate
    return path
def _fetch_roles(http, base):
    try:
        r = http.get(f"{base}{AUTHINFO_PATH}", timeout=TIMEOUT)
        r.raise_for_status()
        roles = _extract_roles(r.json())
    except (requests.RequestException, ValueError) as e:
        _warn(f"{AUTHINFO_PATH} hỏng ({e}); không lấy được roles")
        return []
    if not roles:
        _warn(f"{AUTHINFO_PATH} không trả về roles nào")
    return roles
def _extract_roles(data):
    node = _unwrap(data)
    if isinstance(node, dict):
        for key in ("roles", "backend_roles"):
            value = node.get(key)
            if isinstance(value, list) and value:
                return [str(v) for v in value]
    return []
def _extract_api_id(data):
    node = _unwrap(data)
    if isinstance(node, list):
        node = node[0] if node else None
    if isinstance(node, dict) and node.get("id"):
        return str(node["id"])
    return ""
def _extract_token(resp):
    try:
        node = _unwrap(resp.json())
    except ValueError:
        return None
    if isinstance(node, dict):
        for key in TOKEN_KEYS:
            value = node.get(key)
            if isinstance(value, str) and value:
                return value
    return None