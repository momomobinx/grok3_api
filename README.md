# Grok 3 Web API Wrapper

[English](README.md) | [中文](README-CN.md)

This is a Go-based tool designed to interact with the Grok 3 Web API, offering an OpenAI-compatible endpoint for chat completions. It enables users to send messages to the Grok 3 Web API and receive responses in a format consistent with OpenAI's chat completion API.

## Features

- **OpenAI-Compatible Endpoint**: Supports `/v1/chat/completions` and `/v1/models` endpoints.
- **Streaming Support**: Enables real-time streaming of responses.
- **Model Selection**: Choose between standard and reasoning models.
- **Cookie Management**: Manages multiple cookies.
- **Proxy Support**: Compatible with HTTP and SOCKS5 proxies for network requests.
- **Web Search**: Added search functionality (March 8th), enable with `enableSearch: 1` parameter.
- **Long Text Support**: Use `-longtxt` parameter for file attachments.
- **Custom Cookie Directory**: Set custom cookie directory with `-cookiesDir` parameter.
- **IPv4 Enforcement**: Added `DualStack: false` field to force IPv4 usage.

## Quick Start Guide

### 1. Configure Cookie
- **📂 Storage Location:** Place your Cookie in `.txt` format in the `cookies` folder.
- **📌 Naming Rules:** Each `.txt` file represents one Cookie, and you can name the file freely.
- **⚠️ Content Requirements:** Keep only the `sso=xxxxxx` field, delete other content.

### 2. Launch the Project
- **✏️ Set Token:** Modify the `Token` field in `启动.bat`. Default is: 123456
- **▶ Run** `启动.bat` **for one-click startup**.

### 3. Resolve Authorization Errors
If you encounter **❌ "Unauthorized: Bearer token required"** error, try entering the default Token: 123456 (or your custom Token) in the **Custom Key** of the **SillyTavern API**.

### 4. Fix \n\n Format Issues
- Use the [regex](https://github.com/GhostXia/grok3_api-Fix/blob/main/grok3_%E6%9B%BF%E6%8D%A2%E5%9B%9E%E8%BD%A6%E7%AC%A6%E5%8F%B7.json) by author: [orzogc](https://github.com/orzogc)
- In most cases, simply regenerating the response will fix the issue.

## Configuration

You can configure this tool using command-line flags, environment variables or the request body.

### Command-Line Flags

- `-token`: API authentication token (**required**).
- `-cookie`: Grok cookie(s) for authentication. Accepts a single cookie or a JSON array of cookies.
- `-cookiesDir`: Custom directory path for cookie files (default: "cookies").
- `-longtxt`: Enable long text processing with optional threshold (e.g., `-longtxt 60000`, default: 40000).
- `-httpProxy`: Specifies an HTTP or SOCKS5 proxy URL (e.g., `http://127.0.0.1:1080`).
- `-port`: Sets the server port (default: 8180).

### Request Body Parameters

Some configurations can be set in the request body while using the `/v1/chat/completions` endpoint:

```json
{
  "messages": [],
  "model": "grok-3", // "grok-3" for standard model, "grok-3-reasoning" for reasoning model
  "stream": true, // true for streaming response
  "grokCookies": ["cookie1", "cookie2"], // single cookie string or array of cookies
  "cookieIndex": 1, // cookie index (starting from 1), 0 for auto-selection
  "enableSearch": 1, // 1 to enable web search, 0 to disable
  "keepChat": 1, // 1 to retain chat conversation, 0 to not retain
  "ignoreThinking": 1 // 1 to exclude thinking tokens from reasoning model response
}
```

## Additional Information

❌ **Unsupported File Formats:**
- **Not supported:** `xxxx.xxx.txt` filename format.
- **Please use:** `xxxxx.txt` format directly.

📌 **Other Notes**
- Other features are the same as the original project: [grok3_api](https://github.com/orzogc/grok3_api)
- When using a proxy with connection failures, try `-httpproxy http://127.0.0.1:xxxx`

**Android User Tips**
- Startup command reference (background): `./grok-server -token your-auth-token -cookie xxxxxxx -port 8180 &`
- IPv4 is enforced with `DualStack: false`.
- For detailed usage, see: https://grok.com/share/bGVnYWN5_7cafcf60-ca6b-4097-bdbc-ffaee19b2e2c

## Warning

This tool offers an unofficial OpenAI-compatible API of Grok 3, so your account may be **banned** by xAI if using this tool.

Please do not abuse or use this tool for commercial purposes. Use it at your own risk.

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Special Thanks

- [mem0ai/grok3-api: Unofficial Grok 3 API](https://github.com/mem0ai/grok3-api)
- [RoCry/grok3-api-cf: Grok 3 via API with Cloudflare for free](https://github.com/RoCry/grok3-api-cf/tree/master)
- [orzogc/grok3_api: Original project](https://github.com/orzogc/grok3_api)
- Most code was written by Grok 3, so thanks to Grok 3.
