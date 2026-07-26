#!/bin/bash

set -e 

IMAGE_NAME="nst-rbac-boundary"
VERSION="v1"
BUNDLE_FILE="rbac-bundle.tar"

echo "=========================================="
echo "🚀 BẮT ĐẦU ĐÓNG GÓI RBAC TOOL"
echo "=========================================="

echo "[*] Đang build Docker Image: ${IMAGE_NAME}:${VERSION}..."
docker build -t ${IMAGE_NAME}:${VERSION} .
echo "[+] Build thành công!"

echo "[*] Đang nén thành file ${BUNDLE_FILE}..."
if [ -f "$BUNDLE_FILE" ]; then
    rm "${BUNDLE_FILE}"
fi
docker save ${IMAGE_NAME}:${VERSION} -o ${BUNDLE_FILE}
echo "[+] Đã nén thành file: $(pwd)/${BUNDLE_FILE}"
echo "[+] Dung lượng file:"
ls -lh ${BUNDLE_FILE}

echo "=========================================="
echo "HOÀN TẤT!"
echo "=========================================="