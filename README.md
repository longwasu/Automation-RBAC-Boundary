# RBAC Automation Test Boundary

Công cụ tự động hóa kiểm thử phân quyền (Role-Based Access Control - RBAC) dành cho hệ thống. Kịch bản này tự động giả lập các phiên đăng nhập, đối chiếu quyền hạn của người dùng với ma trận phân quyền (RBAC Matrix), và xuất báo cáo chuẩn JUnit để tích hợp tự động vào 파이프라인 CI/CD.

## 🚀 Tính năng nổi bật
* **Kiểm tra ma trận phân quyền:** Tự động đối chiếu quyền của từng role (admin, guest, staff_sale, v.v.).
* **CI/CD Ready:** Tự động sinh báo cáo `rbac-test-results.xml` chuẩn JUnit phục vụ đọc báo cáo trên các platform CI.

## 📁 Cấu trúc thư mục cơ bản

```text
├── module/
|   ├── auth.py
|   ├── matrix.py
|   ├── oracle.py
|   ├── probe.py
|   └── report.py
├── .gitignore
├── build-bundle.sh
├── config.example.yaml        # Cấu hình danh sách tài khoản và môi trường test
├── invariants.yaml
├── rbac-matrix.py
├── README.md                  # Tài liệu hướng dẫn sử dụng dự án
├── requirements.txt           # Danh sách thư viện phụ thuộc (Dependencies)
└── run.sh                     # Kịch bản khởi chạy an toàn cho CI/CD & Local
```

## 🛠 Yêu cầu hệ thống
* **Hệ điều hành:** Linux / macOS (Để chạy được kịch bản Bash `.sh`).
* **Python:** **>= 3.12** 
* **Trình quản lý gói:** `pip`.

## 🎯 Hướng dẫn sử dụng
1. **Kéo dự án về máy:**
   ```bash
   git clone <url-repo-cua-ban>
   cd Automation-RBAC-Boundary
   ```
2. **Cấu hình dữ liệu đầu vào:**
Đảm bảo bạn đã thiết lập file config.yaml tại thư mục gốc. File này chứa thông tin các tài khoản giả lập, tạo file giống với định dạng của *config.example.yaml*


    g

