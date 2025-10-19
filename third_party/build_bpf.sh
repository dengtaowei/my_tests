#!/bin/bash
# elfutils_cross_compile.sh - 通用交叉编译脚本
# 用法: ./elfutils_cross_compile.sh [ARCH]
# 支持的ARCH: x86_64, arm, arm64, mips, etc.

set -e

# 默认参数
LIBBPF_DIR="libbpf/src"
INSTALL_PREFIX="$PWD/install"
WORK_DIR="$PWD"
ARCH=${1:-"x86"}  # 默认x86_64架构

# 设置不同架构的交叉编译工具链前缀
case "$ARCH" in
    x86)
        HOST="x86_64-linux-gnu"
        TOOLCHAIN_PREFIX="x86_64-linux-gnu"
        ;;
    arm)
        HOST="arm-linux-gnueabi"
        TOOLCHAIN_PREFIX="arm-linux-gnueabi"
        ;;
    arm64)
        HOST="aarch64-linux-gnu"
        TOOLCHAIN_PREFIX="aarch64-linux-gnu"
        ;;
    mips)
        HOST="mips-linux-gnu"
        TOOLCHAIN_PREFIX="mips-linux-gnu"
        ;;
    *)
        echo "不支持的架构: $ARCH"
        echo "支持的架构: x86_64, arm, aarch64, mips"
        exit 1
        ;;
esac

# 配置编译环境
configure_build() {
    cd "${LIBBPF_DIR}"
    
    # 清理旧配置
    [ -f Makefile ] && make clean
    
    echo "[INFO] 配置 ${ARCH} 架构..."
    
    # 设置工具链路径
    export CC="${TOOLCHAIN_PREFIX}-gcc"
    export CXX="${TOOLCHAIN_PREFIX}-g++"
    export AR="${TOOLCHAIN_PREFIX}-ar"
    export RANLIB="${TOOLCHAIN_PREFIX}-ranlib"
    
    # 查找架构特定的库路径
    local lib_paths=(
        "/usr/${TOOLCHAIN_PREFIX}/lib"
        "/usr/lib/${TOOLCHAIN_PREFIX}"
        "/usr/local/${TOOLCHAIN_PREFIX}/lib"
    )
    
    for path in "${lib_paths[@]}"; do
        if [ -d "$path" ]; then
            LIB_PATH="$path"
            break
        fi
    done
    
    if [ -z "$LIB_PATH" ]; then
        echo "[ERROR] 找不到 ${ARCH} 架构的库路径"
        exit 1
    fi
    
    echo "[INFO] 使用库路径: ${LIB_PATH}"


    # ./configure \
    #     --host="${HOST}" \
    #     --prefix="${INSTALL_PREFIX}/${ARCH}"
}

# 编译安装
build_install() {
    echo "[INFO] 开始编译..."
    make -j$(nproc)  BUILD_STATIC_ONLY=1		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=
    
    echo "[INFO] 安装到 ${INSTALL_PREFIX}/${ARCH}"
    make OBJDIR=${INSTALL_PREFIX}/${ARCH}/lib PREFIX=${INSTALL_PREFIX}/${ARCH} install
    
    echo "[INFO] 编译完成!"
    echo "已安装到: ${INSTALL_PREFIX}/${ARCH}"
}

# 主流程
main() {
    echo "===== 开始为 ${ARCH} 架构编译 zlib ====="
    # install_deps
    # download_source
    configure_build
    build_install
}

main