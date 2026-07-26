#!/bin/bash

# Nếu có dòng nào lỗi thì dừng luôn 
set -e

echo "========================================"
echo " KHỞI ĐỘNG RBAC AUTOMATION TEST"
echo "========================================"

echo "[*] Đang kiểm tra và cài đặt dependencies..."
python -m pip install -r requirements.txt > /dev/null

echo "[*] Đang thực thi kịch bản kiểm thử..."
python rbac_matrix.py
