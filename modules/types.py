from typing import Any

class Session:
    """
    Lưu trữ thông tin phiên đăng nhập hợp lệ.
    Cần trả về đối tượng này sau khi gọi API login thành công.
    Args:
        session: Đối tượng requests.Session (chứa cookie/token).
        username: Tên tài khoản đã đăng nhập.
        roles: Danh sách các quyền của tài khoản (VD: ["nst_soc_manager"]).
    """
    def __init__(self, session: Any, username: str, roles: list[str]):
        self.session = session
        self.username = username
        self.roles = roles


class Matrix:
    """
    Chứa dữ liệu Ma trận phân quyền (RBAC Matrix) đọc từ file cấu hình.
    Args:
        raw_data: Dữ liệu thô của ma trận (dạng Dictionary).
    """
    def __init__(self, raw_data: dict[str, Any]):
        self.raw_data = raw_data


class Probe:
    """
    Đại diện cho một kịch bản test (một gói tin) sẽ gửi lên hệ thống.
    Args:
        group: Tên nhóm tính năng để phân loại báo cáo (VD: "User Management").
        method: Phương thức HTTP (GET, POST, PUT, DELETE).
        path: Đường dẫn API (Endpoint) cần test (VD: "/api/users").
        body: Dữ liệu gửi kèm (Payload). Mặc định là None.
    """
    def __init__(self, group: str, method: str, path: str, body: dict[str, Any] | None = None):
        self.group = group
        self.method = method
        self.path = path
        self.body = body


class ProbeResult:
    """
    Kết quả sau khi chạy một Probe. 
    Args:
        username: Tên tài khoản dùng để test.
        roles: Quyền của tài khoản đó.
        group: Nhóm tính năng của API.
        method: Phương thức HTTP đã dùng.
        path: Đường dẫn API đã test.
        status: Mã trạng thái HTTP trả về (VD: 200, 403, 401).
        actual_allow: Hệ thống có cho phép không, dựa vào trường status.
        matrix_expected: Ma trận phân quyền có cho phép không.
        invariant_verdict: Luật bất biến vi phạm (nếu có).
        ok: Được quyết định bởi actual_allow/matrix_expected/invariant_verdict trong reconcile()
    """
    def __init__(self, username: str, roles: list[str], group: str, method: str, path: str, 
                 status: int, actual_allow: bool, matrix_expected: bool, 
                 invariant_verdict: str | None, ok: bool):
        self.username = username
        self.roles = roles
        self.group = group
        self.method = method
        self.path = path
        self.status = status
        self.actual_allow = actual_allow
        self.matrix_expected = matrix_expected
        self.invariant_verdict = invariant_verdict
        self.ok = ok