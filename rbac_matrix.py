from modules.types import Session, Probe, ProbeResult
from modules import matrix, probe, auth, report
import sys


def main():
    if (sys.version_info < (3, 12)):
        print("Yêu cầu Python từ 3.12 trở lên!")
        sys.exit(1)
    
    print("[*] Đang thực hiện đăng nhập các tài khoản giả lập...")
    active_sessions: list[Session] = auth.login_all_users("config.yaml")
    if not active_sessions:
        print("[!] Không có phiên đăng nhập nào hợp lệ. Dừng chương trình.")
        sys.exit(1)

    matrix_data = matrix.load_matrix(active_sessions[0])
    print("[*] Đang khởi tạo kịch bản test...")
    test_cases: list[Probe] = probe.generate_test_cases(matrix_data)
    
    all_results: list[ProbeResult] = []
    for session in active_sessions:
        print(f"  -> Đang test với tài khoản: {session.username} ({session.roles})")
        results_for_user: list[ProbeResult] = probe.execute_probes(session, matrix_data, test_cases)
        all_results.extend(results_for_user) # unpack list

    print("\n[*] Đang tổng hợp báo cáo...")
    report.render_table(all_results)
    report.write_junit(all_results, "rbac-test-results.xml")

    exit_code = 0 if all([r.ok for r in all_results]) else 1
    print(f"[*] Kết thúc kiểm thử. Exit code: {exit_code}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
