#!/bin/bash

# 获取 Git commit ID 的前 8 位作为版本号
VERSION=$(git rev-parse --short=8 HEAD)

# 构建镜像
echo "开始构建 Docker 镜像..."
docker build -t lukbinx/grok3_api:${VERSION} .

# 构建 latest 标签
echo "创建 latest 标签..."
docker tag lukbinx/grok3_api:${VERSION} lukbinx/grok3_api:latest

echo "构建完成！"
echo "镜像标签："
echo "- lukbinx/grok3_api:${VERSION}"
echo "- lukbinx/grok3_api:latest"