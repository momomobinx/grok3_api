package main

import (
    "bytes"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "github.com/google/uuid"
)

// GrokClient 定义与 Grok 3 Web API 交互的客户端
type GrokClient struct {
    newUrl         string            // 创建新对话的端点
    headers        map[string]string // API 请求的 HTTP 头部
    isReasoning    bool              // 是否使用推理模型的标志
    keepChat       bool              // 是否保留聊天历史的标志
    ignoreThinking bool              // 是否忽略响应中的思考标记
}

// NewGrokClient 创建新的 GrokClient 实例
func NewGrokClient(cookies string, isReasoning bool, keepChat bool, ignoreThinking bool) *GrokClient {
    return &GrokClient{
        newUrl: "https://grok.com/rest/app-chat/conversations/new",
        headers: map[string]string{
            "accept":             "*/*",
            "accept-language":    "en-GB,en;q=0.9",
            "content-type":       "application/json",
            "origin":             "https://grok.com",
            "priority":           "u=1, i",
            "referer":            "https://grok.com/",
            "sec-ch-ua":          `"Not/A)Brand";v="8", "Chromium";v="126", "Brave";v="126"`,
            "sec-ch-ua-mobile":   "?0",
            "sec-ch-ua-platform": `"macOS"`,
            "sec-fetch-dest":     "empty",
            "sec-fetch-mode":     "cors",
            "sec-fetch-site":     "same-origin",
            "sec-gpc":            "1",
            "user-agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "cookie":             cookies,
        },
        isReasoning:    isReasoning,
        keepChat:       keepChat,
        ignoreThinking: ignoreThinking,
    }
}

// preparePayload 构建 Grok 3 Web API 的请求负载
func (c *GrokClient) preparePayload(message string, isReasoning bool) map[string]any {
    return map[string]any{
        "customInstructions":        "",
        "deepsearchPreset":          "",
        "disableSearch":             false,
        "enableImageGeneration":     true,
        "enableImageStreaming":      true,
        "enableSideBySide":          true,
        "fileAttachments":           []string{},
        "forceConcise":              false,
        "imageAttachments":          []string{},
        "imageGenerationCount":      2,
        "isPreset":                  false,
        "isReasoning":               isReasoning,
        "message":                   message,
        "modelName":                 "grok-3",
        "returnImageBytes":          false,
        "returnRawGrokInXaiRequest": false,
        "sendFinalMetadata":         true,
        "temporary":                 !c.keepChat,
        "toolOverrides":             map[string]any{},
    }
}

// getModelName 根据 isReasoning 标志返回适当的模型名称
func (c *GrokClient) getModelName() string {
    if c.isReasoning {
        return grok3ReasoningModelName
    }
    return grok3ModelName
}

// RequestBody 表示 POST 请求到 /v1/chat/completions 端点的 JSON 体结构
type RequestBody struct {
    Model            string `json:"model"`
    Messages         []struct {
        Role    string `json:"role"`
        Content string `json:"content"`
    } `json:"messages"`
    Stream           bool   `json:"stream"`
    GrokCookies      any    `json:"grokCookies,omitempty"`
    CookieIndex      uint   `json:"cookieIndex,omitempty"`
    TextBeforePrompt string `json:"textBeforePrompt,omitempty"`
    TextAfterPrompt  string `json:"textAfterPrompt,omitempty"`
    KeepChat         int    `json:"keepChat,omitempty"`
    IgnoreThinking   int    `json:"ignoreThinking,omitempty"`
}

// ResponseToken 表示 Grok 3 Web API 的单个标记响应
type ResponseToken struct {
    Result struct {
        Response struct {
            Token      string `json:"token"`
            IsThinking bool   `json:"isThinking"`
        } `json:"response"`
    } `json:"result"`
}

// ModelData 表示 OpenAI 兼容响应的模型元数据
type ModelData struct {
    Id       string `json:"id"`
    Object   string `json:"object"`
    Owned_by string `json:"owned_by"`
}

// ModelList 包含 OpenAI 兼容端点的可用模型
type ModelList struct {
    Object string      `json:"object"`
    Data   []ModelData `json:"data"`
}

const (
    grok3ModelName          = "grok-3"
    grok3ReasoningModelName = "grok-3-reasoning"
    completionsPath         = "/v1/chat/completions"
    listModelsPath          = "/v1/models"
)

// 全局配置变量
var (
    apiToken         *string
    grokCookies      []string
    textBeforePrompt *string
    textAfterPrompt  *string
    keepChat         *bool
    ignoreThinking   *bool
    httpProxy        *string
    cookiesDir       *string // 新增：cookie 文件夹路径
    httpClient       = &http.Client{Timeout: 30 * time.Minute}
    nextCookieIndex = struct {
        sync.Mutex
        index uint
    }{}
)

// sendMessage 发送消息到 Grok 3 Web API 并返回响应体
func (c *GrokClient) sendMessage(message string, stream bool) (io.ReadCloser, error) {
    payload := c.preparePayload(message, c.isReasoning)
    jsonPayload, err := json.Marshal(payload)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal payload: %v", err)
    }

    req, err := http.NewRequest(http.MethodPost, c.newUrl, bytes.NewBuffer(jsonPayload))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %v", err)
    }

    for key, value := range c.headers {
        req.Header.Set(key, value)
    }

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to send request: %v", err)
    }
    if resp.StatusCode != http.StatusOK {
        defer resp.Body.Close()
        body, err := io.ReadAll(resp.Body)
        if err != nil {
            return nil, fmt.Errorf("the Grok API error: %d %s", resp.StatusCode, resp.Status)
        }
        return nil, fmt.Errorf("the Grok API error: %d %s, response body: %s", resp.StatusCode, resp.Status, string(body))
    }

    if stream {
        return resp.Body, nil
    }
    defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %v", err)
    }
    return io.NopCloser(bytes.NewReader(body)), nil
}

type OpenAIChatCompletionMessage struct {
    Role    string `json:"role"`
    Content string `json:"content"`
}

type OpenAIChatCompletionChunkChoice struct {
    Index        int                         `json:"index"`
    Delta        OpenAIChatCompletionMessage `json:"delta"`
    FinishReason string                      `json:"finish_reason"`
}

type OpenAIChatCompletionChunk struct {
    ID      string                            `json:"id"`
    Object  string                            `json:"object"`
    Created int64                             `json:"created"`
    Model   string                            `json:"model"`
    Choices []OpenAIChatCompletionChunkChoice `json:"choices"`
}

type OpenAIChatCompletionChoice struct {
    Index        int                         `json:"index"`
    Message      OpenAIChatCompletionMessage `json:"message"`
    FinishReason string                      `json:"finish_reason"`
}

type OpenAIChatCompletionUsage struct {
    PromptTokens     int `json:"prompt_tokens"`
    CompletionTokens int `json:"completion_tokens"`
    TotalTokens      int `json:"total_tokens"`
}

type OpenAIChatCompletion struct {
    ID      string                       `json:"id"`
    Object  string                       `json:"object"`
    Created int64                        `json:"created"`
    Model   string                       `json:"model"`
    Choices []OpenAIChatCompletionChoice `json:"choices"`
    Usage   OpenAIChatCompletionUsage    `json:"usage"`
}

// createOpenAIStreamingResponse 将 Grok 3 流响应转换为 OpenAI 流格式
func (c *GrokClient) createOpenAIStreamingResponse(grokStream io.Reader) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/event-stream")
        w.Header().Set("Cache-Control", "no-cache")
        w.Header().Set("Connection", "keep-alive")

        flusher, ok := w.(http.Flusher)
        if !ok {
            log.Println("Streaming unsupported")
            http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
            return
        }

        completionID := "chatcmpl-" + uuid.New().String()

        startChunk := OpenAIChatCompletionChunk{
            ID:      completionID,
            Object:  "chat.completion.chunk",
            Created: time.Now().Unix(),
            Model:   c.getModelName(),
            Choices: []OpenAIChatCompletionChunkChoice{
                {
                    Index: 0,
                    Delta: OpenAIChatCompletionMessage{
                        Role: "assistant",
                    },
                    FinishReason: "",
                },
            },
        }
        fmt.Fprintf(w, "data: %s\n\n", mustMarshal(startChunk))
        flusher.Flush()

        isThinking := false
        buffer := make([]byte, 1024)
        for {
            n, err := grokStream.Read(buffer)
            if err != nil {
                if err == io.EOF {
                    break
                }
                log.Printf("Error reading stream: %v", err)
                return
            }

            chunk := string(buffer[:n])
            lines := strings.Split(chunk, "\n")
            for _, line := range lines {
                line = strings.TrimSpace(line)
                if line == "" {
                    continue
                }

                var token ResponseToken
                if err := json.Unmarshal([]byte(line), &token); err != nil {
                    continue
                }

                respToken := token.Result.Response.Token
                if c.ignoreThinking && token.Result.Response.IsThinking {
                    continue
                } else if token.Result.Response.IsThinking {
                    if !isThinking {
                        respToken = "<think>\n" + respToken
                    }
                    isThinking = true
                } else if isThinking {
                    respToken = respToken + "\n</think>\n\n"
                    isThinking = false
                }

                if respToken != "" {
                    chunk := OpenAIChatCompletionChunk{
                        ID:      completionID,
                        Object:  "chat.completion.chunk",
                        Created: time.Now().Unix(),
                        Model:   c.getModelName(),
                        Choices: []OpenAIChatCompletionChunkChoice{
                            {
                                Index: 0,
                                Delta: OpenAIChatCompletionMessage{
                                    Content: respToken,
                                },
                                FinishReason: "",
                            },
                        },
                    }
                    fmt.Fprintf(w, "data: %s\n\n", mustMarshal(chunk))
                    flusher.Flush()
                }
            }
        }

        finalChunk := OpenAIChatCompletionChunk{
            ID:      completionID,
            Object:  "chat.completion.chunk",
            Created: time.Now().Unix(),
            Model:   c.getModelName(),
            Choices: []OpenAIChatCompletionChunkChoice{
                {
                    Index:        0,
                    Delta:        OpenAIChatCompletionMessage{},
                    FinishReason: "stop",
                },
            },
        }
        fmt.Fprintf(w, "data: %s\n\n", mustMarshal(finalChunk))
        flusher.Flush()
        fmt.Fprintf(w, "data: [DONE]\n\n")
        flusher.Flush()
    }
}

// createOpenAIFullResponse 将完整的 Grok 3 响应转换为 OpenAI 格式
func (c *GrokClient) createOpenAIFullResponse(grokFull io.Reader) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var fullResponse strings.Builder
        buf := new(strings.Builder)
        _, err := io.Copy(buf, grokFull)
        if err != nil {
            log.Printf("Reading response error: %v", err)
            http.Error(w, fmt.Sprintf("Reading response error: %v", err), http.StatusInternalServerError)
            return
        }

        isThinking := false
        lines := strings.Split(buf.String(), "\n")
        for _, line := range lines {
            line = strings.TrimSpace(line)
            if line == "" {
                continue
            }

            var token ResponseToken
            if err := json.Unmarshal([]byte(line), &token); err != nil {
                continue
            }

            respToken := token.Result.Response.Token
            if c.ignoreThinking && token.Result.Response.IsThinking {
                continue
            } else if token.Result.Response.IsThinking {
                if !isThinking {
                    respToken = "<think>\n" + respToken
                }
                isThinking = true
            } else if isThinking {
                respToken = respToken + "\n</think>\n\n"
                isThinking = false
            }

            fullResponse.WriteString(respToken)
        }

        openAIResponse := c.createOpenAIFullResponseBody(fullResponse.String())
        w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(openAIResponse); err != nil {
            log.Printf("Encoding response error: %v", err)
            http.Error(w, fmt.Sprintf("Encoding response error: %v", err), http.StatusInternalServerError)
        }
    }
}

// createOpenAIFullResponseBody 创建非流式请求的 OpenAI 响应体
func (c *GrokClient) createOpenAIFullResponseBody(content string) OpenAIChatCompletion {
    return OpenAIChatCompletion{
        ID:      "chatcmpl-" + uuid.New().String(),
        Object:  "chat.completion",
        Created: time.Now().Unix(),
        Model:   c.getModelName(),
        Choices: []OpenAIChatCompletionChoice{
            {
                Index: 0,
                Message: OpenAIChatCompletionMessage{
                    Role:    "assistant",
                    Content: content,
                },
                FinishReason: "stop",
            },
        },
        Usage: OpenAIChatCompletionUsage{
            PromptTokens:     -1,
            CompletionTokens: -1,
            TotalTokens:      -1,
        },
    }
}

// mustMarshal 将值序列化为 JSON 字符串
func mustMarshal(v any) string {
    b, err := json.Marshal(v)
    if err != nil {
        panic(err)
    }
    return string(b)
}

// getCookieIndex 以轮询方式选择下一个 cookie 索引
func getCookieIndex(len int, cookieIndex uint) uint {
    if cookieIndex == 0 || cookieIndex > uint(len) {
        nextCookieIndex.Lock()
        defer nextCookieIndex.Unlock()
        index := nextCookieIndex.index
        nextCookieIndex.index = (nextCookieIndex.index + 1) % uint(len)
        return index % uint(len)
    }
    return cookieIndex - 1
}

// handleChatCompletion 处理 /v1/chat/completions 的 POST 请求
func handleChatCompletion(w http.ResponseWriter, r *http.Request) {
    log.Printf("Request from %s for %s", r.RemoteAddr, completionsPath)

    if r.URL.Path != completionsPath {
        log.Printf("Requested Path %s Not Found", r.URL.Path)
        http.Error(w, "Requested Path Not Found", http.StatusNotFound)
        return
    }

    if r.Method != http.MethodPost {
        log.Printf("Method %s Not Allowed", r.Method)
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
        return
    }

    authHeader := r.Header.Get("Authorization")
    if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
        log.Println("Unauthorized: Bearer token required")
        http.Error(w, "Unauthorized: Bearer token required", http.StatusUnauthorized)
        return
    }

    token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
    if token != *apiToken {
        log.Println("Unauthorized: Invalid token")
        http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
        return
    }

    body := RequestBody{KeepChat: -1, IgnoreThinking: -1}
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        log.Println("Bad Request: Invalid JSON")
        http.Error(w, "Bad Request: Invalid JSON", http.StatusBadRequest)
        return
    }

    var cookie string
    var cookieIndex uint
    if body.GrokCookies != nil {
        if ck, ok := body.GrokCookies.(string); ok {
            cookie = ck
        } else if list, ok := body.GrokCookies.([]any); ok {
            if len(list) > 0 {
                cookieIndex = getCookieIndex(len(list), body.CookieIndex)
                if ck, ok := list[cookieIndex].(string); ok {
                    cookie = ck
                }
            }
        }
    }
    cookie = strings.TrimSpace(cookie)
    if cookie == "" && len(grokCookies) > 0 {
        cookieIndex = getCookieIndex(len(grokCookies), body.CookieIndex)
        cookie = grokCookies[cookieIndex]
    }
    cookie = strings.TrimSpace(cookie)
    if cookie == "" {
        log.Println("Error: No Grok 3 cookie")
        http.Error(w, "Error: No Grok 3 cookie", http.StatusBadRequest)
        return
    }

    messages := body.Messages
    if len(messages) == 0 {
        log.Println("Bad Request: No messages provided")
        http.Error(w, "Bad Request: No messages provided", http.StatusBadRequest)
        return
    }

    messageJson := bytes.NewBuffer([]byte{})
    jsonEncoder := json.NewEncoder(messageJson)
    jsonEncoder.SetEscapeHTML(false)
    jsonEncoder.SetIndent("", "")
    err := jsonEncoder.Encode(messages)
    if err != nil {
        log.Println("Error: Encoding JSON failed")
        http.Error(w, "Error: Encoding JSON failed", http.StatusInternalServerError)
        return
    }
    if messageJson.Len() <= 2 {
        log.Println("Bad Request: No user message found")
        http.Error(w, "Bad Request: No user message found", http.StatusBadRequest)
        return
    }

    var beforePromptText, afterPromptText string
    if body.TextBeforePrompt != "" {
        beforePromptText = body.TextBeforePrompt
    } else {
        beforePromptText = *textBeforePrompt
    }
    if body.TextAfterPrompt != "" {
        afterPromptText = body.TextAfterPrompt
    } else {
        afterPromptText = *textAfterPrompt
    }
    message := beforePromptText + messageJson.String() + afterPromptText

    isReasoning := strings.TrimSpace(body.Model) == grok3ReasoningModelName
    keepConversation := body.KeepChat > 0 || (body.KeepChat < 0 && *keepChat)
    ignoreThink := body.IgnoreThinking > 0 || (body.IgnoreThinking < 0 && *ignoreThinking)

    grokClient := NewGrokClient(cookie, isReasoning, keepConversation, ignoreThink)
    log.Printf("Use the cookie with index %d to request Grok 3 Web API", cookieIndex+1)
    respReader, err := grokClient.sendMessage(message, body.Stream)
    if err != nil {
        log.Printf("Error: %v", err)
        http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
        return
    }
    defer respReader.Close()

    if body.Stream {
        grokClient.createOpenAIStreamingResponse(respReader)(w, r)
    } else {
        grokClient.createOpenAIFullResponse(respReader)(w, r)
    }
}

// listModels 处理 /v1/models 的 GET 请求
func listModels(w http.ResponseWriter, r *http.Request) {
    log.Printf("Request from %s for %s", r.RemoteAddr, listModelsPath)

    if r.URL.Path != listModelsPath {
        log.Printf("Requested Path %s Not Found", r.URL.Path)
        http.Error(w, "Requested Path Not Found", http.StatusNotFound)
        return
    }

    if r.Method != http.MethodGet {
        log.Printf("Method %s Not Allowed", r.Method)
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
        return
    }

    list := ModelList{
        Object: "list",
        Data: []ModelData{
            {Id: grok3ModelName, Object: "model", Owned_by: "xAI"},
            {Id: grok3ReasoningModelName, Object: "model", Owned_by: "xAI"},
        },
    }

    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(list); err != nil {
        log.Printf("Encoding response error: %v", err)
        http.Error(w, fmt.Sprintf("Encoding response error: %v", err), http.StatusInternalServerError)
    }
}

// loadCookiesFromDir 从指定目录加载 cookie 文件
func loadCookiesFromDir(dir string) error {
    if _, err := os.Stat(dir); os.IsNotExist(err) {
        return fmt.Errorf("cookies directory does not exist: %s", dir)
    }

    files, err := os.ReadDir(dir)
    if err != nil {
        return fmt.Errorf("failed to read directory %s: %v", dir, err)
    }

    grokCookies = []string{}
    for _, file := range files {
        if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") {
            filePath := filepath.Join(dir, file.Name())
            content, err := os.ReadFile(filePath)
            if err != nil {
                log.Printf("Warning: Failed to read cookie file %s: %v", filePath, err)
                continue
            }
            cookie := strings.TrimSpace(string(content))
            if cookie != "" {
                grokCookies = append(grokCookies, cookie)
                log.Printf("Loaded cookie from %s", filePath)
            }
        }
    }
    return nil
}

// main 设置并启动 HTTP 服务器
func main() {
    apiToken = flag.String("token", "", "Authentication token (GROK3_AUTH_TOKEN)")
    cookie := flag.String("cookie", "", "Grok cookie (GROK3_COOKIE)")
    cookiesDir = flag.String("cookiesDir", "cookies", "Directory containing cookie.txt files")
    textBeforePrompt = flag.String("textBeforePrompt", "For the data below, entries with the role 'system' are system information, entries with the role 'assistant' are messages you have previously sent, entries with the role 'user' are messages sent by the user. You need to respond to the user's last message accordingly based on the corresponding data.", "Text before the prompt")
    textAfterPrompt = flag.String("textAfterPrompt", "", "Text after the prompt")
    keepChat = flag.Bool("keepChat", false, "Don't delete the chat conversation after request")
    ignoreThinking = flag.Bool("ignoreThinking", false, "Ignore the thinking content while using the reasoning model")
    httpProxy = flag.String("httpProxy", "", "HTTP/SOCKS5 proxy")
    port := flag.Uint("port", 8180, "Server port")
    flag.Parse()

    if *port > 65535 {
        log.Fatalf("Server port %d is greater than 65535", *port)
    }

    *apiToken = strings.TrimSpace(*apiToken)
    if *apiToken == "" {
        *apiToken = os.Getenv("GROK3_AUTH_TOKEN")
        if *apiToken == "" {
            log.Fatal("Authentication token (GROK3_AUTH_TOKEN) is unset")
        }
    }

    *cookie = strings.TrimSpace(*cookie)
    if *cookie == "" {
        *cookie = strings.TrimSpace(os.Getenv("GROK3_COOKIE"))
    }
    if *cookie != "" {
        err := json.Unmarshal([]byte(*cookie), &grokCookies)
        if err != nil {
            grokCookies = []string{*cookie}
        }
    }

    if len(grokCookies) == 0 {
        err := loadCookiesFromDir(*cookiesDir)
        if err != nil {
            log.Printf("Warning: Failed to load cookies from directory %s: %v", *cookiesDir, err)
        }
        if len(grokCookies) == 0 {
            log.Fatal("No valid cookies found in command line, environment, or cookies directory")
        }
    }

    *httpProxy = strings.TrimSpace(*httpProxy)
    if *httpProxy != "" {
        proxyURL, err := url.Parse(*httpProxy)
        if err == nil {
            httpClient.Transport = &http.Transport{
                Proxy: http.ProxyURL(proxyURL),
                DialContext: (&net.Dialer{
                    Timeout:   30 * time.Second,
                    KeepAlive: 30 * time.Second,
                }).DialContext,
                ForceAttemptHTTP2:   true,
                MaxIdleConns:        10,
                IdleConnTimeout:     600 * time.Second,
                TLSHandshakeTimeout: 20 * time.Second,
            }
        } else {
            log.Fatalf("Parsing HTTP/SOCKS5 proxy error：%v", err)
        }
    }

    http.HandleFunc(completionsPath, handleChatCompletion)
    http.HandleFunc(listModelsPath, listModels)
    log.Printf("Server starting on :%d with %d cookies loaded", *port, len(grokCookies))
    log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
