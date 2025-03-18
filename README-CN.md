# Grok 3 Web API 封装工具

[English](README.md) | [中文](README-CN.md)

这是一个基于Go语言的工具，设计用于与Grok 3 Web API交互，提供与OpenAI兼容的聊天补全端点。它使用户能够向Grok 3 Web API发送消息，并以与OpenAI聊天补全API一致的格式接收响应。

## 功能特点

- **OpenAI兼容端点**：支持 `/v1/chat/completions` 和 `/v1/models` 端点。
- **流式响应支持**：实现实时流式响应。
- **模型选择**：可选择标准模型或推理模型。
- **Cookie管理**：管理多个Cookie。
- **代理支持**：兼容HTTP和SOCKS5代理进行网络请求。
- **网络搜索**：新增搜索功能（3月8日），通过 `enableSearch: 1` 参数启用。
- **长文本支持**：使用 `-longtxt` 参数进行文件附件上传。
- **自定义Cookie目录**：通过 `-cookiesDir` 参数设置自定义Cookie目录。
- **IPv4强制使用**：添加 `DualStack: false` 字段强制使用IPv4。

## 快速使用指南

### 1. 配置 Cookie
- **📂 存放位置：** 将你的 Cookie 以 `.txt` 格式存放在 `cookies` 文件夹中。
- **📌 命名规则：** 每个 `.txt` 文件代表一条 Cookie，文件名可自由命名。
- **⚠️ 内容要求：** 仅保留 `sso=xxxxxx` 字段，删除其他内容。

### 2. 启动项目
- **✏️ 写入Token：** 修改 `启动.bat` 中的 `Token` 字段。默认为：123456
- **▶ 运行** `启动.bat` **一键启动**。

### 3. 解决授权错误
如果遇到 **❌ "Unauthorized: Bearer token required"** 错误，请尝试在 **SillyTavern API** 的 **自定义密钥** 中输入默认 Token：123456（或者你自己设定的Token）。

### 4. 解决\n\n格式问题
- 请使用[正则表达式](https://github.com/GhostXia/grok3_api-Fix/blob/main/grok3_%E6%9B%BF%E6%8D%A2%E5%9B%9E%E8%BD%A6%E7%AC%A6%E5%8F%B7.json)，作者：[orzogc](https://github.com/orzogc)
- 大多数情况下，重新生成一下回复就能解决问题。

## 配置选项

你可以使用命令行标志或环境变量配置客户端。

### 命令行标志

- `-token`：API认证令牌（**必需**）。
- `-cookie`：用于认证的Grok cookie。接受单个cookie或JSON数组格式的多个cookie。
- `-cookiesDir`：自定义cookie文件目录路径（默认："cookies"）。
- `-longtxt`：启用长文本处理，可选阈值（例如，`-longtxt 60000`，默认：40000）。
- `-httpProxy`：指定HTTP或SOCKS5代理URL（例如，`http://127.0.0.1:1080`）。
- `-port`：设置服务器端口（默认：8180）。

### 请求体参数

使用 `/v1/chat/completions` 端点时，可以在请求体中设置一些配置：

```json
{
  "messages": [],
  "model": "grok-3", // "grok-3" 为标准模型，"grok-3-reasoning" 为推理模型
  "stream": true, // true 表示流式响应
  "grokCookies": ["cookie1", "cookie2"], // 单个cookie字符串或cookie数组
  "cookieIndex": 1, // cookie索引（从1开始），0表示自动选择
  "enableSearch": 1, // 1表示启用网络搜索，0表示禁用
  "keepChat": 1, // 1表示保留聊天对话，0表示不保留
  "ignoreThinking": 1 // 1表示从推理模型响应中排除思考令牌
}
```

## 附加信息

❌ **不支持的文件格式：**
- **不支持：** `xxxx.xxx.txt` 形式的文件名。
- **请直接使用：** `xxxxx.txt` 格式。

📌 **其他说明**
- 其余功能与原项目相同，参考：[grok3_api](https://github.com/orzogc/grok3_api)
- 使用代理时，如果出现连接失败提示，尝试使用 `-httpproxy http://127.0.0.1:xxxx`

**安卓用户提示**
- 启动命令参考（后台启动）：`./grok-server -token your-auth-token -cookie xxxxxxx -port 8180 &`
- 已用 `DualStack: false` 强制使用IPv4。
- 具体使用参考：https://grok.com/share/bGVnYWN5_7cafcf60-ca6b-4097-bdbc-ffaee19b2e2c

## 警告

本工具提供了Grok 3的非官方OpenAI兼容API，因此使用本工具可能导致您的账户被xAI**封禁**。

请勿滥用或将此工具用于商业目的。使用风险自负。

## 许可证

本项目采用GNU Affero通用公共许可证v3.0 - 详情请参阅[LICENSE](LICENSE)文件。

## 特别感谢

- [mem0ai/grok3-api: 非官方Grok 3 API](https://github.com/mem0ai/grok3-api)
- [RoCry/grok3-api-cf: 通过Cloudflare免费使用Grok 3 API](https://github.com/RoCry/grok3-api-cf/tree/master)
- [orzogc/grok3_api: 原始项目](https://github.com/orzogc/grok3_api)
- 大部分代码由Grok 3编写，感谢Grok 3。