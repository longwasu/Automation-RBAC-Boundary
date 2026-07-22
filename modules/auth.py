"""task-B — authentication & session.

Three steps; the order is forced because each one needs the previous:
    POST /auth/login  {username, password}   -> security_authentication + nst-user
    GET  /hosts/apis                         -> api id                  -> nst-api
    POST /api/login   {idHost, force:false}  -> nst-token

Public API:
    login(base_url, username, password, verify_tls=False, roles=None) -> Session
    get_manager_host_id(session) -> str
    prepare_session(session, api_id) -> str | None

Self-test:  python -m modules.auth --selftest --config config.yaml
"""
from __future__ import annotations
import os
import sys
import requests
from common.types import Session

LOGIN_PATH = "/auth/login"
HOSTS_APIS_PATH = "/hosts/apis"
API_LOGIN_PATH = "/api/login"
AUTHINFO_PATH = "/api/v1/auth/authinfo"
XSRF_HEADER = {"osd-xsrf": "kibana"}
SESSION_COOKIE = "security_authentication"
NST_USER_COOKIE = "nst-user"
NST_API_COOKIE = "nst-api"
NST_TOKEN_COOKIE = "nst-token"
TOKEN_KEYS = ("nst-token", "nst_token", "nstToken", "token", "jwt", "access_token")
TIMEOUT = 15

class AuthError(RuntimeError):
    """Could not establish a usable session."""

def _warn(msg):
    print(f"[auth] {msg}", file=sys.stderr)


def _unwrap(data):
    """Many responses wrap the payload in {"data": {...}} — look inside if so."""
    return data.get("data", data) if isinstance(data, dict) else data


def _new_http(base, verify_tls):
    http = requests.Session()
    http.verify = verify_tls
    http.headers.update(XSRF_HEADER)
    http.base_url = base
    if not verify_tls:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return http


def set_nst_cookies(http, username=None, api_id=None, token=None):
    """Attach the NST cookies that do not arrive via Set-Cookie."""
    if username:
        http.cookies.set(NST_USER_COOKIE, username)
    if api_id:
        http.cookies.set(NST_API_COOKIE, api_id)
    if token:
        http.cookies.set(NST_TOKEN_COOKIE, token)


def login(base_url, username, password, verify_tls=False, roles=None) -> Session:
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
    return Session(http=http, username=username,
                   roles=roles if roles is not None else _fetch_roles(http, base))


def get_manager_host_id(session: Session) -> str:
    http = session.http
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
    return api_id


def fetch_nst_token(session: Session, api_id, force=False):
    http = session.http
    base = getattr(http, "base_url", "")
    try:
        r = http.post(f"{base}{API_LOGIN_PATH}",
                      json={"idHost": api_id, "force": bool(force)}, timeout=TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as e:
        _warn(f"{API_LOGIN_PATH} (idHost={api_id!r}) failed: {e}")
        return None

    token = http.cookies.get(NST_TOKEN_COOKIE) or _extract_token(r)
    if not token:
        _warn(f"{API_LOGIN_PATH} returned no recognisable token")
        return None
    set_nst_cookies(http, token=token)
    return token


def prepare_session(session: Session, api_id, force=False):
    set_nst_cookies(session.http, api_id=api_id)
    return fetch_nst_token(session, api_id, force)


def _fetch_roles(http, base):
    try:
        r = http.get(f"{base}{AUTHINFO_PATH}", timeout=TIMEOUT)
        r.raise_for_status()
        roles = _extract_roles(r.json())
    except (requests.RequestException, ValueError) as e:
        _warn(f"{AUTHINFO_PATH} failed ({e}); roles unresolved")
        return []
    if not roles:
        _warn(f"{AUTHINFO_PATH} returned no roles")
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
    if isinstance(node, list):                       # [{"id": "manager-nst", ...}]
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


def _selftest(config_path):
    from common.config import load_config
    cfg = load_config(config_path)
    ok = True

    for u in cfg.users_low_to_high():
        try:
            s = login(cfg.base_url, u.username, u.password, cfg.verify_tls)
            api_id = get_manager_host_id(s)
            token = prepare_session(s, api_id)
        except AuthError as e:
            ok = False
            print(f"[ERR] {e}")
            continue
        print(f"[OK]  {u.username:24} id={api_id}")
        print(f"      config={list(u.roles or [])} server={s.roles or '(unresolved)'}")

    return 0 if ok else 1


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="task-B auth self-test")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--config", default="config.yaml")
    a = ap.parse_args()
    try:
        sys.exit(_selftest(a.config) if a.selftest else 0)
    except AuthError as e:
        print(f"[ERR] {e}", file=sys.stderr)
        sys.exit(1)