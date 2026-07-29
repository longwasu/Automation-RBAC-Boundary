# RBAC Automation Test Boundary

Công cụ tự động hóa kiểm thử phân quyền (Role-Based Access Control - RBAC) dành cho hệ thống. Kịch bản này tự động giả lập các phiên đăng nhập, đối chiếu quyền hạn của người dùng với ma trận phân quyền (RBAC Matrix), và xuất báo cáo chuẩn JUnit để tích hợp tự động vào CI/CD.

## 🚀 Tính năng nổi bật
* **Kiểm tra ma trận phân quyền:** Tự động đối chiếu quyền của từng role (admin, guest, staff_sale, v.v.).
* **CI/CD Ready:** Tự động sinh báo cáo `rbac-test-results.xml` chuẩn JUnit phục vụ đọc báo cáo trên các platform CI.

## 📁 Cấu trúc thư mục cơ bản

```text
├── module/
|   ├── auth.py                 # Xử lý logic xác thực
|   ├── matrix.py               # Xử lý logic của ma trận phân quyền
|   ├── oracle.py               # Chứa logic đối chiếu kết quả mong đợi vs thực tế
|   ├── probe.py                # Các request thăm dò tới API mục tiêu
|   ├── report.py               # Render bảng kết quả và xuất file XML
|   └── types.py                # Định nghĩa các class Session, Matrix, Probe, ProbeResult
├── .gitignore
├── build-bundle.sh             # Kịch bản đóng gói
├── config.example.yaml         # Chứa định dạng danh sách tài khoản
├── invariants.yaml             # Chứa luật bất biến
├── rbac-matrix.py              # Entry point
├── README.md                   
├── requirements.txt            # Danh sách thư viện phụ thuộc (Dependencies)
└── run.sh                      # Kịch bản khởi chạy an toàn cho CI/CD & Local
```

## 🛠 Yêu cầu hệ thống
* **Hệ điều hành:** Linux / macOS (Để chạy được kịch bản Bash `.sh`).
* **Python:** **>= 3.12** 
* **Trình quản lý gói:** `pip`.

## 🎯 Hướng dẫn sử dụng
**1. Kéo dự án về máy:**
   ```bash
   git clone <url-repo-cua-ban>
   cd Automation-RBAC-Boundary
   ```
**2. Cấu hình dữ liệu đầu vào:**
Đảm bảo bạn đã thiết lập file config.yaml tại thư mục gốc. File này chứa thông tin các tài khoản giả lập, tạo file giống với định dạng của `config.example.yaml`

**3. Khởi chạy kiểm thử**
Cách để chạy kịch bản kiểm thử này:

*Cách A: Chạy tự động bằng Bash Script (Khuyên dùng cho CI/CD hoặc Git Bash trên Windows)*
```bash
bash run.sh
```
*Cách B: Chạy thủ công*
```bash
# 1. Tạo môi trường ảo
python -m venv venv

# 2. Kích hoạt môi trường ảo 
.\venv\Scripts\activate
# Trên Linux/macOS/Git Bash: 
source venv/bin/activate

# 3. Cài đặt thư viện
pip install -r requirements.txt

# 4. Chạy kịch bản
python rbac_matrix.py
```

*Cách C: Chạy trong docker image (môi trường Linux/Git Bash)*
```bash
# 1. Build docker image, tạo ra file .tar
./build-bundle.sh

# 2. Giải nén file .tar, tạo ra docker image
docker load -i <tên file.tar>

# 3. Chạy docker image
docker run -it --rm <tên docker image>
```

## 📊 Đọc kết quả báo cáo
Sau khi chạy thành công, hệ thống sẽ trả về 2 dạng báo cáo:
1. **Console UI:** Hiển thị ma trận kết quả pass/fail trên Terminal (sử dụng `rich.table.Table`).
2. **XML Report:** File `rbac-test-results.xml` được sinh ra tại thư mục gốc. Dùng cho hệ thống CI/CD

