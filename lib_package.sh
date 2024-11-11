#!/bin/bash

# 检查是否提供了目标文件名
if [ -z "$1" ]; then
    echo "用法: $0 <可执行文件>"
    exit 1
fi

EXECUTABLE=$1

# 1. 编译可执行文件（动态链接）
echo "编译可执行文件..."
g++ -o $EXECUTABLE shield10086.cpp -lnetfilter_queue -lnfnetlink -lev -lpthread
if [ $? -ne 0 ]; then
    echo "编译失败"
    exit 1
fi

# 2. 创建 libs 文件夹
echo "创建 libs 文件夹..."
mkdir -p libs

# 3. 收集依赖库并复制到 libs 文件夹
echo "收集依赖库..."
for lib in $(ldd ./$EXECUTABLE | grep "=> /" | awk '{print $3}'); do
    cp -v "$lib" libs/
done

# 4. 使用 patchelf 设置 RPATH 为 libs 文件夹
echo "设置 RPATH..."
patchelf --set-rpath '$ORIGIN/libs' ./$EXECUTABLE

# 5. 打包文件夹
echo "打包可执行文件和库..."
tar -czvf ${EXECUTABLE}_package.tar.gz $EXECUTABLE libs/

echo "打包完成: ${EXECUTABLE}_package.tar.gz"
