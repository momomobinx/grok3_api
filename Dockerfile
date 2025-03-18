# 构建阶段
FROM golang:1.24-alpine AS builder

# 设置工作目录
WORKDIR /app

# 设置 Go 模块代理和必要的 git 支持
ENV GOPROXY=https://goproxy.cn,direct
RUN apk add --no-cache git

# 复制 go.mod 和 go.sum 文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# 运行阶段
FROM alpine:latest

WORKDIR /app

# 设置环境变量及默认值
ENV PORT=8180 \
    KEEP_CHAT="false" \
    IGNORE_THINKING="false" \
    CHARS_LIMIT="50000" \
    TEXT_BEFORE_PROMPT="" \
    TEXT_AFTER_PROMPT="" \
    COOKIE_FILE=""



# 从构建阶段复制编译好的二进制文件
COPY --from=builder /app/main .

# 暴露端口
EXPOSE 8180

# 使用环境变量构建启动命令
ENTRYPOINT ["./main", \
    "-port=${PORT}", \
    "-token=${GROK3_AUTH_TOKEN}", \
    "-cookie=${GROK3_COOKIE}", \
    "-textBeforePrompt=${TEXT_BEFORE_PROMPT}", \
    "-textAfterPrompt=${TEXT_AFTER_PROMPT}", \
    "-keepChat=${KEEP_CHAT}", \
    "-ignoreThinking=${IGNORE_THINKING}", \
    "-charsLimit=${CHARS_LIMIT}", \
    "-httpProxy=${http_proxy}"]