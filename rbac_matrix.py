from typing import List, Dict, Optional, Any
from modules import matrix, probe, auth, report
import sys


class Session:
    """
    Lưu trữ thông tin phiên đăng nhập hợp lệ.
    Cần trả về đối tượng này sau khi gọi API login thành công.
    Args:
        session: Đối tượng requests.Session (chứa cookie/token).
        username: Tên tài khoản đã đăng nhập.
        roles: Danh sách các quyền của tài khoản (VD: ["nst_soc_manager"]).
    """
    def __init__(self, session: Any, username: str, roles: List[str]):
        self.session = session
        self.username = username
        self.roles = roles


class Matrix:
    """
    Chứa dữ liệu Ma trận phân quyền (RBAC Matrix) đọc từ file cấu hình.
    Args:
        raw_data: Dữ liệu thô của ma trận (dạng Dictionary).
    """
    def __init__(self, raw_data: Dict[str, Any]):
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
    def __init__(self, group: str, method: str, path: str, body: Optional[Dict[str, Any]] = None):
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
        invariant_verdict: Kết quả kiểm tra tính bất biến (nếu có).
        ok: True nếu actual_allow KHỚP với matrix_expected, ngược lại là False.
    """
    def __init__(self, username: str, roles: List[str], group: str, method: str, path: str, 
                 status: int, actual_allow: bool, matrix_expected: bool, 
                 invariant_verdict: Optional[str], ok: bool):
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
        

def main():
    print("[*] Đang khởi tạo kịch bản test...")
    test_cases: List[Probe] = probe.generate_test_cases()
    print("[*] Đang nạp RBAC Matrix từ config.yaml...")
    matrix_data: Matrix = matrix.load_matrix("config.yaml") 
    
    print("[*] Đang thực hiện đăng nhập các tài khoản giả lập...")
    active_sessions: List[Session] = auth.login_all_users("config.yaml") 
    if not active_sessions:
        print("[!] Không có phiên đăng nhập nào hợp lệ. Dừng chương trình.")
        sys.exit(1)

    for session in active_sessions:
        matrix_data = matrix.load_matrix(session)
    
    all_results: List[ProbeResult] = []
    for session in active_sessions:
        print(f"  -> Đang test với tài khoản: {session.username} ({session.roles})")
        results_for_user: List[ProbeResult] = probe.execute_probes(session, matrix_data, test_cases)
        all_results.extend(results_for_user)

    print("\n[*] Đang tổng hợp báo cáo...")
    report.render_table(all_results)
    print("[*] Hoàn tất!")


if __name__ == "__main__":
    main()

