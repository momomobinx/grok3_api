package main

import (
	"bytes"
	"encoding/base64"
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
	"unicode/utf8"

	"github.com/google/uuid"
)

// GrokClient 定义了与 Grok 3 Web API 交互的客户端。
type GrokClient struct {
	headers        map[string]string // HTTP 请求头
	isReasoning    bool              // 是否使用推理模型
	enableSearch   bool              // 是否启用网络搜索
	keepChat       bool              // 是否保留聊天历史
	ignoreThinking bool              // 是否忽略思考令牌
	longTxt        bool              // 是否启用长文本处理并自动选择上传方法
	messageLimit   int               // 选择上传方法的字符阈值（默认：40000）
	httpClient     *http.Client      // 可自定义的 HTTP 客户端
}

// NewGrokClient 创建一个新的 GrokClient 实例。
func NewGrokClient(cookie string, isReasoning, enableSearch, keepChat, ignoreThinking, longTxt bool) *GrokClient {
	return &GrokClient{
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
			"cookie":             cookie,
		},
		isReasoning:    isReasoning,
		enableSearch:   enableSearch,
		keepChat:       keepChat,
		ignoreThinking: ignoreThinking,
		longTxt:        longTxt,
		messageLimit:   40000, // 固定阈值用于方法选择
		httpClient:     &http.Client{Timeout: 30 * time.Minute},
	}
}

// UploadFileRequest 表示上传文件的请求结构。
type UploadFileRequest struct {
	Content      string `json:"content"`
	FileMimeType string `json:"fileMimeType"`
	FileName     string `json:"fileName"`
}

// UploadFileResponse 表示上传文件的响应结构。
type UploadFileResponse struct {
	FileMetadataId string `json:"fileMetadataId"`
}

// ResponseToken 表示 Grok 3 Web API 的单个令牌响应。
type ResponseToken struct {
	Result struct {
		Response struct {
			Token      string `json:"token"`
			IsThinking bool   `json:"isThinking"`
		} `json:"response"`
	} `json:"result"`
}

// RequestBody 表示 /v1/chat/completions 的 JSON 请求体结构。
type RequestBody struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Stream         bool `json:"stream"`
	GrokCookies    any  `json:"grokCookies,omitempty"`
	CookieIndex    uint `json:"cookieIndex,omitempty"`
	EnableSearch   int  `json:"enableSearch,omitempty"`
	LongTxt        int  `json:"longTxt,omitempty"`
	KeepChat       int  `json:"keepChat,omitempty"`
	IgnoreThinking int  `json:"ignoreThinking,omitempty"`
}

// OpenAIChatCompletionMessage 定义 OpenAI 响应的消息结构。
type OpenAIChatCompletionMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIChatCompletionChunkChoice 定义流式响应中的选择结构。
type OpenAIChatCompletionChunkChoice struct {
	Index        int                         `json:"index"`
	Delta        OpenAIChatCompletionMessage `json:"delta"`
	FinishReason string                      `json:"finish_reason"`
}

// OpenAIChatCompletionChunk 表示流式响应格式。
type OpenAIChatCompletionChunk struct {
	ID      string                            `json:"id"`
	Object  string                            `json:"object"`
	Created int64                             `json:"created"`
	Model   string                            `json:"model"`
	Choices []OpenAIChatCompletionChunkChoice `json:"choices"`
}

// OpenAIChatCompletionChoice 定义完整响应中的选择结构。
type OpenAIChatCompletionChoice struct {
	Index        int                         `json:"index"`
	Message      OpenAIChatCompletionMessage `json:"message"`
	FinishReason string                      `json:"finish_reason"`
}

// OpenAIChatCompletionUsage 跟踪令牌使用情况。
type OpenAIChatCompletionUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// OpenAIChatCompletion 表示非流式响应格式。
type OpenAIChatCompletion struct {
	ID      string                       `json:"id"`
	Object  string                       `json:"object"`
	Created int64                        `json:"created"`
	Model   string                       `json:"model"`
	Choices []OpenAIChatCompletionChoice `json:"choices"`
	Usage   OpenAIChatCompletionUsage    `json:"usage"`
}

// ModelData 表示 OpenAI 兼容响应的模型元数据。
type ModelData struct {
	Id       string `json:"id"`
	Object   string `json:"object"`
	Owned_by string `json:"owned_by"`
}

// ModelList 包含 OpenAI 兼容端点的可用模型。
type ModelList struct {
	Object string      `json:"object"`
	Data   []ModelData `json:"data"`
}

const (
	newChatUrl              = "https://grok.com/rest/app-chat/conversations/new" // 新会话端点
	uploadFileUrl           = "https://grok.com/rest/app-chat/upload-file"       // 文件上传端点
	completionsPath         = "/v1/chat/completions"                             // 聊天完成端点
	listModelsPath          = "/v1/models"                                       // 模型列表端点
	grok3ModelName          = "grok-3"                                           // 标准模型名称
	grok3ReasoningModelName = "grok-3-reasoning"                                 // 推理模型名称
)

// 全局配置变量
var (
	apiToken        *string
	grokCookies     []string
	keepChat        *bool
	ignoreThinking  *bool
	longTxt         *bool
	httpProxy       *string
	cookiesDir      *string
	httpClient      = &http.Client{Timeout: 30 * time.Minute}
	nextCookieIndex = struct {
		sync.Mutex
		index uint
	}{}
)

// uploadFile 通过 API 上传内容并返回文件 ID。
func (c *GrokClient) uploadFile(content string) (string, error) {
	payload := UploadFileRequest{
		Content:      base64.StdEncoding.EncodeToString([]byte(content)),
		FileMimeType: "text/plain",
		FileName:     fmt.Sprintf("message-%s.txt", uuid.New().String()),
	}
	resp, err := c.doRequest(http.MethodPost, uploadFileUrl, payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取上传响应失败: %v", err)
	}
	var uploadResp UploadFileResponse
	if err := json.Unmarshal(body, &uploadResp); err != nil || uploadResp.FileMetadataId == "" {
		return "", fmt.Errorf("无效的上传响应: %s", string(body))
	}
	return uploadResp.FileMetadataId, nil
}

// createLocalFile 创建临时本地文件并返回其路径。
func (c *GrokClient) createLocalFile(content string) (string, error) {
	fileName := fmt.Sprintf("temp-%s.txt", uuid.New().String())
	tempFile, err := os.Create(fileName)
	if err != nil {
		return "", fmt.Errorf("创建文件失败: %v", err)
	}
	defer tempFile.Close()
	if _, err := tempFile.WriteString(content); err != nil {
		return "", fmt.Errorf("写入文件失败: %v", err)
	}
	return fileName, nil
}

// createMessagesAttachment 创建包含消息历史的文本文件。
func (c *GrokClient) createMessagesAttachment(messages []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}) (string, error) {
	var builder strings.Builder
	for _, msg := range messages {
		builder.WriteString(fmt.Sprintf("[%s]\n%s\n\n", msg.Role, msg.Content))
	}

	fileName := fmt.Sprintf("messages-%s.txt", uuid.New().String())
	tempFile, err := os.Create(fileName)
	if err != nil {
		return "", fmt.Errorf("创建文件失败: %v", err)
	}
	defer tempFile.Close()

	if _, err := tempFile.WriteString(builder.String()); err != nil {
		return "", fmt.Errorf("写入文件失败: %v", err)
	}
	return fileName, nil
}

// preparePayload 构建 API 请求的有效负载。
func (c *GrokClient) preparePayload(message string, fileAttachments []string) map[string]any {
	return map[string]any{
		"message":         message,
		"modelName":       "grok-3",
		"isReasoning":     c.isReasoning,
		"temporary":       !c.keepChat,
		"fileAttachments": fileAttachments,
		"toolOverrides":   map[string]any{"webSearch": c.enableSearch},
	}
}

// doRequest 发送 HTTP 请求并返回响应。
func (c *GrokClient) doRequest(method, url string, payload any) (*http.Response, error) {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化有效负载失败: %v", err)
	}
	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("API 错误: %d %s, 响应体: %s", resp.StatusCode, resp.Status, string(body))
		}
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	return resp, nil
}

// sendMessage 发送消息到 Grok 3 Web API，支持自动文件处理和容错切换。
func (c *GrokClient) sendMessage(messages []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}, stream bool) (io.ReadCloser, error) {
	var fileAttachments []string
	messageBuf := bytes.NewBuffer([]byte{})
	jsonEncoder := json.NewEncoder(messageBuf)
	jsonEncoder.SetEscapeHTML(false)
	if err := jsonEncoder.Encode(messages); err != nil {
		return nil, fmt.Errorf("消息编码失败: %v", err)
	}
	message := messageBuf.String()

	if c.longTxt && len(messages) > 0 {
		charCount := utf8.RuneCountInString(message)
		var fileId string
		var err error

		if charCount >= c.messageLimit {
			// 首先尝试 API 上传（适用于大消息）
			fileContent, _ := c.createMessagesAttachment(messages) // 格式化消息历史
			fileId, err = c.uploadFile(fileContent)
			if err != nil {
				log.Printf("API 上传失败: %v，尝试本地文件创建", err)
				// 切换到本地文件创建
				fileId, err = c.createMessagesAttachment(messages)
				if err != nil {
					return nil, fmt.Errorf("本地文件创建失败: %v（API 上传也已失败）", err)
				}
				defer os.Remove(fileId) // 确保清理本地文件
			} else {
				// API 上传成功，调整消息内容
				message = "请按照附件中的说明进行回复。"
			}
		} else if charCount > 0 {
			// 首先尝试本地文件创建（适用于小消息）
			fileId, err = c.createMessagesAttachment(messages)
			if err != nil {
				log.Printf("本地文件创建失败: %v，尝试 API 上传", err)
				// 切换到 API 上传
				fileContent, _ := c.createMessagesAttachment(messages)
				fileId, err = c.uploadFile(fileContent)
				if err != nil {
					return nil, fmt.Errorf("API 上传失败: %v（本地文件创建也已失败）", err)
				}
				message = "请按照附件中的说明进行回复。"
			} else {
				defer os.Remove(fileId) // 确保清理本地文件
			}
		}

		if fileId != "" {
			fileAttachments = append(fileAttachments, fileId)
		}
	}

	payload := c.preparePayload(message, fileAttachments)
	resp, err := c.doRequest(http.MethodPost, newChatUrl, payload)
	if err != nil {
		return nil, err
	}
	if stream {
		return resp.Body, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

// parseGrok3StreamingJson 解析 Grok 3 的流式响应。
func (c *GrokClient) parseGrok3StreamingJson(stream io.Reader, handler func(respToken string)) {
	isThinking := false
	decoder := json.NewDecoder(stream)
	for {
		var token ResponseToken
		err := decoder.Decode(&token)
		if err == io.EOF {
			break
		} else if err != nil {
			log.Printf("解析 JSON 错误: %v", err)
			break
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
			handler(respToken)
		}
	}
}

// CreateOpenAIStreamingResponse 将 Grok 3 流式响应转换为 OpenAI 格式。
func (c *GrokClient) CreateOpenAIStreamingResponse(grokStream io.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "流式传输不支持", http.StatusInternalServerError)
			return
		}

		completionID := "chatcmpl-" + uuid.New().String()
		modelName := grok3ModelName
		if c.isReasoning {
			modelName = grok3ReasoningModelName
		}

		startChunk := OpenAIChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   modelName,
			Choices: []OpenAIChatCompletionChunkChoice{
				{Index: 0, Delta: OpenAIChatCompletionMessage{Role: "assistant"}, FinishReason: ""},
			},
		}
		fmt.Fprintf(w, "data: %s\n\n", mustMarshal(startChunk))
		flusher.Flush()

		c.parseGrok3StreamingJson(grokStream, func(respToken string) {
			chunk := OpenAIChatCompletionChunk{
				ID:      completionID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   modelName,
				Choices: []OpenAIChatCompletionChunkChoice{
					{Index: 0, Delta: OpenAIChatCompletionMessage{Content: respToken}, FinishReason: ""},
				},
			}
			fmt.Fprintf(w, "data: %s\n\n", mustMarshal(chunk))
			flusher.Flush()
		})

		finalChunk := OpenAIChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   modelName,
			Choices: []OpenAIChatCompletionChunkChoice{
				{Index: 0, Delta: OpenAIChatCompletionMessage{}, FinishReason: "stop"},
			},
		}
		fmt.Fprintf(w, "data: %s\n\n", mustMarshal(finalChunk))
		flusher.Flush()

		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	}
}

// CreateOpenAIFullResponse 将 Grok 3 完整响应转换为 OpenAI 格式。
func (c *GrokClient) CreateOpenAIFullResponse(grokFull io.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var fullResponse strings.Builder
		c.parseGrok3StreamingJson(grokFull, func(respToken string) {
			fullResponse.WriteString(respToken)
		})

		modelName := grok3ModelName
		if c.isReasoning {
			modelName = grok3ReasoningModelName
		}

		response := OpenAIChatCompletion{
			ID:      "chatcmpl-" + uuid.New().String(),
			Object:  "chat.completion",
			Created: time.Now().Unix(),
			Model:   modelName,
			Choices: []OpenAIChatCompletionChoice{
				{
					Index:        0,
					Message:      OpenAIChatCompletionMessage{Role: "assistant", Content: fullResponse.String()},
					FinishReason: "stop",
				},
			},
			Usage: OpenAIChatCompletionUsage{PromptTokens: -1, CompletionTokens: -1, TotalTokens: -1},
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, fmt.Sprintf("编码响应错误: %v", err), http.StatusInternalServerError)
		}
	}
}

// mustMarshal 将值序列化为 JSON，失败时抛出异常。
func mustMarshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// getCookieIndex 以轮询方式选择下一个 Cookie 索引。
func getCookieIndex(len int, cookieIndex uint) uint {
	if cookieIndex == 0 || cookieIndex > uint(len) {
		nextCookieIndex.Lock()
		defer nextCookieIndex.Unlock()
		index := nextCookieIndex.index
		nextCookieIndex.index = (nextCookieIndex.index + 1) % uint(len)
		return index % uint(len)
	} else {
		return cookieIndex - 1
	}
}

// loadCookiesFromDir 从指定目录加载 Cookie。
func loadCookiesFromDir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("Cookie 目录不存在: %s", dir)
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("读取目录 %s 失败: %v", dir, err)
	}

	grokCookies = []string{}
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") {
			filePath := filepath.Join(dir, file.Name())
			content, err := os.ReadFile(filePath)
			if err != nil {
				log.Printf("警告: 读取 Cookie 文件 %s 失败: %v", filePath, err)
				continue
			}
			cookie := strings.TrimSpace(string(content))
			if cookie != "" {
				grokCookies = append(grokCookies, cookie)
				log.Printf("从 %s 加载 Cookie", filePath)
			}
		}
	}
	return nil
}

// handleChatCompletion 处理 /v1/chat/completions 的 POST 请求。
func handleChatCompletion(w http.ResponseWriter, r *http.Request) {
	log.Printf("来自 %s 的请求，路径: %s", r.RemoteAddr, completionsPath)

	if r.Method != http.MethodPost || r.URL.Path != completionsPath {
		log.Printf("无效请求: 方法 %s, 路径 %s", r.Method, r.URL.Path)
		http.Error(w, "方法不允许或路径未找到", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		log.Println("未授权: 需要 Bearer 令牌")
		http.Error(w, "未授权: 需要 Bearer 令牌", http.StatusUnauthorized)
		return
	}

	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if token != *apiToken {
		log.Println("未授权: 无效令牌")
		http.Error(w, "未授权: 无效令牌", http.StatusUnauthorized)
		return
	}

	var body RequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		log.Println("错误请求: 无效 JSON")
		http.Error(w, "错误请求: 无效 JSON", http.StatusBadRequest)
		return
	}

	if len(body.Messages) == 0 {
		log.Println("错误请求: 未提供消息")
		http.Error(w, "错误请求: 未提供消息", http.StatusBadRequest)
		return
	}

	// 选择 Cookie
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
		log.Println("错误: 无 Grok 3 Cookie")
		http.Error(w, "错误: 无 Grok 3 Cookie", http.StatusBadRequest)
		return
	}

	// 使用请求体覆盖默认配置
	isReasoning := strings.TrimSpace(body.Model) == grok3ReasoningModelName
	enableSearch := body.EnableSearch > 0
	keepChatVal := *keepChat
	if body.KeepChat > 0 {
		keepChatVal = true
	} else if body.KeepChat == 0 {
		keepChatVal = false
	}
	ignoreThinkingVal := *ignoreThinking
	if body.IgnoreThinking > 0 {
		ignoreThinkingVal = true
	} else if body.IgnoreThinking == 0 {
		ignoreThinkingVal = false
	}
	longTxtVal := *longTxt
	if body.LongTxt > 0 {
		longTxtVal = true
	} else if body.LongTxt == 0 {
		longTxtVal = false
	}

	client := NewGrokClient(cookie, isReasoning, enableSearch, keepChatVal, ignoreThinkingVal, longTxtVal)
	log.Printf("使用索引 %d 的 Cookie 请求 Grok 3 Web API", cookieIndex+1)

	respReader, err := client.sendMessage(body.Messages, body.Stream)
	if err != nil {
		log.Printf("错误: %v", err)
		http.Error(w, fmt.Sprintf("错误: %v", err), http.StatusInternalServerError)
		return
	}
	defer respReader.Close()

	if body.Stream {
		client.CreateOpenAIStreamingResponse(respReader)(w, r)
	} else {
		client.CreateOpenAIFullResponse(respReader)(w, r)
	}
}

// listModels 处理 /v1/models 的 GET 请求。
func listModels(w http.ResponseWriter, r *http.Request) {
	log.Printf("来自 %s 的请求，路径: %s", r.RemoteAddr, listModelsPath)

	if r.Method != http.MethodGet || r.URL.Path != listModelsPath {
		log.Printf("无效请求: 方法 %s, 路径 %s", r.Method, r.URL.Path)
		http.Error(w, "方法不允许或路径未找到", http.StatusNotFound)
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
		log.Printf("编码响应错误: %v", err)
		http.Error(w, fmt.Sprintf("编码响应错误: %v", err), http.StatusInternalServerError)
	}
}

// main 设置 HTTP 服务器并开始监听。
func main() {
	apiToken = flag.String("token", "", "认证令牌 (GROK3_AUTH_TOKEN)")
	cookie := flag.String("cookie", "", "Grok Cookie (GROK3_COOKIE)")
	cookiesDir = flag.String("cookiesDir", "cookies", "包含 cookie.txt 文件的目录")
	longTxt = flag.Bool("longtxt", false, "启用长文本处理并自动选择上传方法")
	keepChat = flag.Bool("keepChat", false, "保留聊天会话")
	ignoreThinking = flag.Bool("ignoreThinking", false, "忽略思考内容")
	httpProxy = flag.String("httpProxy", "", "HTTP/SOCKS5 代理")
	port := flag.Uint("port", 8180, "服务器端口")
	flag.Parse()

	if *port > 65535 {
		log.Fatalf("服务器端口 %d 超过 65535", *port)
	}

	*apiToken = strings.TrimSpace(*apiToken)
	if *apiToken == "" {
		*apiToken = os.Getenv("GROK3_AUTH_TOKEN")
		if *apiToken == "" {
			log.Fatal("认证令牌 (GROK3_AUTH_TOKEN) 未设置")
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
			log.Printf("警告: 从目录 %s 加载 Cookie 失败: %v", *cookiesDir, err)
		}
		if len(grokCookies) == 0 {
			log.Fatal("未找到有效 Cookie")
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
			log.Fatalf("解析 HTTP/SOCKS5 代理错误: %v", err)
		}
	}

	http.HandleFunc(completionsPath, handleChatCompletion)
	http.HandleFunc(listModelsPath, listModels)
	log.Printf("服务器启动于 :%d，长文本处理: %v，已加载 Cookie 数量: %d", *port, *longTxt, len(grokCookies))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
