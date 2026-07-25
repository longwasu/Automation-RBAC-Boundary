#!/bin/bash

# Nếu có dòng nào lỗi thì dừng luôn 
set -e

echo "========================================"
echo " KHỞI ĐỘNG RBAC AUTOMATION TEST"
echo "========================================"

echo "[*] Đang kiểm tra và cài đặt dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

echo "[*] Đang thực thi kịch bản kiểm thử..."
python3 main.py
