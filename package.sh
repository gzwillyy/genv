#!/bin/bash

# 检查输入的可执行文件名
if [ -z "$1" ]; then
    echo "用法: $0 <可执行文件名>"
    exit 1
fi


EXECUTABLE=$1
NFNETLINK_SRC_DIR="/root/genv/libnfnetlink-1.0.1/src"  # 替换为 libnfnetlink.a 的实际路径

# 1. 编译并进行完全静态链接，同时使用 -fPIE 和 -fPIC 实现位置无关代码
echo "编译并进行静态链接，启用位置无关代码..."
g++ -o $EXECUTABLE shield10086.cpp pm2_manager.cpp \
    /usr/lib/x86_64-linux-gnu/libnetfilter_queue.a \
    $NFNETLINK_SRC_DIR/libnfnetlink.a \
    /usr/lib/x86_64-linux-gnu/libev.a \
    -lpthread -static -fPIE -fPIC

if [ $? -ne 0 ]; then
    echo "编译失败"
    exit 1
fi

# 2. 检查并安装 UPX（如果未安装）
if ! command -v upx &> /dev/null; then
    echo "UPX 未安装，正在下载并安装..."
    wget https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-amd64_linux.tar.xz
    tar -xvf upx-4.0.2-amd64_linux.tar.xz
    sudo mv upx-4.0.2-amd64_linux/upx /usr/local/bin/
    rm -rf upx-4.0.2-amd64_linux*
    if [ $? -ne 0 ]; then
        echo "UPX 安装失败"
        exit 1
    fi
fi

# 3. 使用 UPX 加壳
echo "使用 UPX 压缩可执行文件..."
upx --best $EXECUTABLE
if [ $? -ne 0 ]; then
    echo "UPX 压缩失败"
    exit 1
fi

# 4. 打包成 tar.gz 文件
PACKAGE_NAME="${EXECUTABLE}_package.tar.gz"
echo "打包 $EXECUTABLE 为 $PACKAGE_NAME..."
tar -czvf $PACKAGE_NAME $EXECUTABLE

echo "打包完成: $PACKAGE_NAME"
