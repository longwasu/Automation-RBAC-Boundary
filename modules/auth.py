from __future__ import annotations
import os
import sys
from typing import List
import requests
import yaml

_shapes = None
def shapes():
    """Load module rbac_matrix theo kiểu lazy (chỉ load khi cần) để tránh lỗi vòng lặp import (circular import)."""
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

def _unwrap(data):
    """Bóc tách lớp 'data' bao bọc bên ngoài JSON response nếu có dạng {"data": {...}} thành {...}."""
    return data.get("data", data) if isinstance(data, dict) else data


def _new_http(base, verify_tls):
    """Khởi tạo cấu hình mạng: Tạo đối tượng requests.Session với các header giả lập trình duyệt, URL gốc và thiết lập TLS."""
    http = requests.Session()
    http.verify = verify_tls
    http.headers.update(BROWSER_HEADERS)
    http.headers["Origin"] = base
    http.headers["Referer"] = f"{base}/"
    http.base_url = base
    if not verify_tls:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception as e:
            print(f"Xảy ra lỗi khi xác định verify_tls header: {e}")
            pass
    return http


def set_nst_cookies(http, username=None, api_id=None, token=None):
    """Gắn các cookie cần thiết bao gồm (username, api_id, nst-token) vào phiên kết nối HTTP."""
    if username:
        http.cookies.set(NST_USER_COOKIE, username)
    if api_id:
        http.cookies.set(NST_API_COOKIE, api_id)
    if token:
        http.cookies.set(NST_TOKEN_COOKIE, token)


def login(base_url, username, password, verify_tls=False, roles=None):
    """Gửi request đăng nhập bằng tài khoản/mật khẩu để lấy cookie cốt lõi và trả về đối tượng Session."""
    base = base_url.rstrip("/")
    http = _new_http(base, verify_tls)
    try:
        resp = http.post(f"{base}{LOGIN_PATH}",
                         json={"username": username, "password": password},
                         timeout=TIMEOUT)
    except requests.RequestException as e:
        raise AuthError(f"{username}: cannot reach {base}{LOGIN_PATH}: {e}") from e
    
    if resp.status_code == 401:
        raise AuthError(f"{username}: login failed (HTTP {resp.status_code})")
    
    set_nst_cookies(http, username=username)
    return shapes().Session(session=http, username=username,
                            roles=roles if roles is not None else _fetch_roles(http, base))


def get_manager_host_id(session) -> str:
    """Gọi API lấy mã định danh của tài khoản từ máy chủ hệ thống."""
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
    http.api_id = api_id
    return api_id


def fetch_nst_token(session, api_id, force=False):
    """Dựa vào các token trước đó để gọi API/login lấy nst-token"""
    http = session.session
    base = getattr(http, "base_url", "")
    try:
        r = http.post(f"{base}{API_LOGIN_PATH}",
                      json={"idHost": api_id, "force": bool(force)}, timeout=TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as e:
        return None

    token = http.cookies.get(NST_TOKEN_COOKIE) or _extract_token(r)
    if not token:
        return None
    set_nst_cookies(http, token=token)
    return token

def login_all_users(config_path: str) -> List:
    """Đọc cấu hình và chạy luồng đăng nhập 3 bước cho toàn bộ tài khoản, in kết quả kiểm tra."""
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

        if api_id is None:
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
        sessions.append(s)
    return sessions


def _read_config(path: str):
    """Đọc và parse file YAML cấu hình để lấy URL hệ thống, cờ TLS và danh sách tài khoản cần test."""
    config_path = _resolve_config(path)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        
        system = raw.get("system") or {}
        users = []
        for u in raw.get("test_users", []):
            users.append({
                "username": u["username"],
                "password": u.get("password", ""),
                "roles": [u["role"]] if u.get("role") else []
            })
        base_url = system["base_url"]
        verify_tls = bool(system.get("verify_tls", False))
        return base_url, verify_tls, users
    
    except FileNotFoundError:
        raise FileNotFoundError(f"Lỗi: Không thể tìm thấy file cấu hình tại: {config_path}")
    except yaml.YAMLError as exc:
        raise ValueError(f"Lỗi cú pháp YAML trong file config:\n{exc}")
    except KeyError as exc:
        raise ValueError(f"Lỗi cấu trúc config: Thiếu trường dữ liệu bắt buộc {exc}")
    except TypeError as exc:
        raise ValueError(f"Lỗi kiểu dữ liệu trong config. Vui lòng kiểm tra lại cấu trúc: {exc}")

def _resolve_config(path: str) -> str:
    """Tìm kiếm và trả về đường dẫn tuyệt đối chính xác của file cấu hình nhằm hỗ trợ chạy script từ thư mục khác."""
    if os.path.exists(path):
        return path
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, os.path.basename(path))
    if os.path.exists(candidate):
        return candidate
    return path


def _fetch_roles(http, base):
    """Gọi API authinfo để đối chiếu và lấy danh sách quyền (roles) thực tế của tài khoản hiện tại từ máy chủ."""
    try:
        r = http.get(f"{base}{AUTHINFO_PATH}", timeout=TIMEOUT)
        r.raise_for_status()
        roles = _extract_roles(r.json())
    except (requests.RequestException, ValueError) as e:
        print(f"[ERR] {e}")
        return []
    return roles


def _extract_roles(data):
    """Trích xuất mảng quyền từ response payload (tìm ở cả 'roles' và 'backend_roles')."""
    node = _unwrap(data)
    if isinstance(node, dict):
        for key in ("roles", "backend_roles"):
            value = node.get(key)
            if isinstance(value, list) and value:
                return [str(v) for v in value]
    return []


def _extract_api_id(data):
    """Trích xuất chuỗi ID của máy chủ từ mảng dữ liệu trả về."""
    node = _unwrap(data)
    if isinstance(node, list):
        node = node[0] if node else None
    if isinstance(node, dict) and node.get("id"):
        return str(node["id"])
    return ""


def _extract_token(resp):
    """Quét JSON body để tìm token truy cập theo danh sách các từ khóa phổ biến (TOKEN_KEYS)."""
    try:
        node = _unwrap(resp.json())
    except ValueError as e:
        print(f"ValueError: {e}")
        return None
    if isinstance(node, dict):
        for key in TOKEN_KEYS:
            value = node.get(key)
            if isinstance(value, str) and value:
                return value
    return None