#!/bin/bash
# ~/source/llama.cpp/scripts/install.sh

set -euo pipefail

HOME_DIR="/home/paulplee"
SOURCE_DIR="${HOME_DIR}/source/llama.cpp"
BUILD_BIN="${SOURCE_DIR}/build/bin"

# Read version from the build
VERSION=$("${BUILD_BIN}/llama-server" --version 2>&1 \
  | grep '^version:' \
  | awk '{print $2}')

INSTALL_DIR="/opt/llama.cpp/${VERSION}"

echo "Installing llama.cpp ${VERSION} to ${INSTALL_DIR}..."

sudo mkdir -p "${INSTALL_DIR}/bin" "${INSTALL_DIR}/lib"

# Copy binaries
sudo cp "${BUILD_BIN}"/llama-server \
        "${BUILD_BIN}"/llama-cli \
        "${BUILD_BIN}"/llama-bench \
        "${BUILD_BIN}"/llama-quantize \
        "${INSTALL_DIR}/bin/"

# Copy shared libraries
sudo cp "${BUILD_BIN}"/lib*.so* "${INSTALL_DIR}/lib/"

# Fix internal symlinks in lib dir
cd "${INSTALL_DIR}/lib"
for f in *.so.*.*; do
  base=$(echo "$f" | cut -d. -f1-2)   # e.g. libggml.so.0
  sudo ln -sf "$f" "${base}"
done

# Swing the 'current' pointer — atomic, services see this immediately
sudo ln -sfn "${INSTALL_DIR}" /opt/llama.cpp/current

# Update /usr/local/bin symlinks
sudo ln -sf /opt/llama.cpp/current/bin/llama-server /usr/local/bin/llama-server
sudo ln -sf /opt/llama.cpp/current/bin/llama-cli    /usr/local/bin/llama-cli
sudo ln -sf /opt/llama.cpp/current/bin/llama-bench  /usr/local/bin/llama-bench

# Register libs with the dynamic linker
echo "/opt/llama.cpp/current/lib" | sudo tee /etc/ld.so.conf.d/llama.conf
sudo ldconfig

echo "Done. Active version: $(readlink /opt/llama.cpp/current)"