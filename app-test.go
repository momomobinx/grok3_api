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
	"strconv"
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
	uploadMessage  bool              // 是否将消息上传为文件
	keepChat       bool              // 是否保留聊天历史
	ignoreThinking bool              // 是否忽略思考令牌
	enableUpload   bool              // 是否启用文件上传
}

// NewGrokClient 创建一个新的 GrokClient 实例。
func NewGrokClient(cookie string, isReasoning, enableSearch, uploadMessage, keepChat, ignoreThinking, enableUpload bool) *GrokClient {
	return &GrokClient{
		headers: map[string]string{
			"accept":                      "*/*",
			"accept-encoding":             "gzip, deflate, br, zstd",
			"accept-language":             "zh-CN,zh;q=0.9",
			"content-type":                "application/json",
			"authority":                   "grok.com",
			"origin":                      "https://grok.com",
			"dnt":                         "1",
			"priority":                    "u=1, i",
			"referer":                     "https://grok.com/",
			"sec-ch-ua":                   `"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"`,
			"sec-ch-ua-arch":              `"x86"`,
			"sec-ch-ua-bitness":           `"64"`,
			"sec-ch-ua-full-version":      `"134.0.6998.89"`,
			"sec-ch-ua-full-version-list": `"Chromium";v="134.0.6998.89", "Not:A-Brand";v="24.0.0.0", "Google Chrome";v="134.0.6998.89"`,
			"sec-ch-ua-mobile":            "?0",
			"sec-ch-ua-model":             `""`,
			"sec-ch-ua-platform":          `"Windows"`,
			"sec-ch-ua-platform-version":  `"19.0.0"`,
			"sec-fetch-dest":              "empty",
			"sec-fetch-mode":              "cors",
			"sec-fetch-site":              "same-origin",
			"sec-gpc":                     "1",
			"user-agent":                  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			"cookie":                      cookie,
		},
		isReasoning:    isReasoning,
		enableSearch:   enableSearch,
		uploadMessage:  uploadMessage,
		keepChat:       keepChat,
		ignoreThinking: ignoreThinking,
		enableUpload:   enableUpload,
	}
}

// ToolOverrides 定义工具覆盖选项。
type ToolOverrides struct {
	ImageGen     bool `json:"imageGen"`
	TrendsSearch bool `json:"trendsSearch"`
	WebSearch    bool `json:"webSearch"`
	XMediaSearch bool `json:"xMediaSearch"`
	XPostAnalyze bool `json:"xPostAnalyze"`
	XSearch      bool `json:"xSearch"`
}

// preparePayload 构造 Grok 3 Web API 的请求负载。
func (c *GrokClient) preparePayload(message string, fileId string) map[string]any {
	var toolOverrides any = ToolOverrides{}
	if c.enableSearch {
		toolOverrides = map[string]any{}
	}

	fileAttachments := []string{}
	if fileId != "" {
		fileAttachments = []string{fileId}
	}

	return map[string]any{
		"deepsearchPreset":          "",
		"disableSearch":             false,
		"enableImageGeneration":     true,
		"enableImageStreaming":      true,
		"enableSideBySide":          true,
		"fileAttachments":           fileAttachments,
		"forceConcise":              false,
		"imageAttachments":          []string{},
		"imageGenerationCount":      2,
		"isPreset":                  false,
		"isReasoning":               c.isReasoning,
		"message":                   message,
		"modelName":                 "grok-3",
		"returnImageBytes":          false,
		"returnRawGrokInXaiRequest": false,
		"sendFinalMetadata":         true,
		"temporary":                 !c.keepChat,
		"toolOverrides":             toolOverrides,
		"webpageUrls":               []string{},
	}
}

// getModelName 根据 isReasoning 标志返回模型名称。
func (c *GrokClient) getModelName() string {
	if c.isReasoning {
		return grok3ReasoningModelName
	}
	return grok3ModelName
}

// RequestBody 表示 /v1/chat/completions 的 POST 请求 JSON 结构体。
type RequestBody struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Stream           bool   `json:"stream"`
	GrokCookies      any    `json:"grokCookies,omitempty"`
	CookieIndex      uint   `json:"cookieIndex,omitempty"`
	EnableSearch     int    `json:"enableSearch,omitempty"`
	UploadMessage    int    `json:"uploadMessage,omitempty"`
	TextBeforePrompt string `json:"textBeforePrompt,omitempty"`
	TextAfterPrompt  string `json:"textAfterPrompt,omitempty"`
	KeepChat         int    `json:"keepChat,omitempty"`
	IgnoreThinking   int    `json:"ignoreThinking,omitempty"`
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

// UploadFileRequest 表示上传文件的请求结构体。
type UploadFileRequest struct {
	Content      string `json:"content"`
	FileMimeType string `json:"fileMimeType"`
	FileName     string `json:"fileName"`
}

// UploadFileResponse 表示上传文件的响应结构体。
type UploadFileResponse struct {
	FileMetadataId string `json:"fileMetadataId"`
}

const (
	newChatUrl              = "https://grok.com/rest/app-chat/conversations/new"
	uploadFileUrl           = "https://grok.com/rest/app-chat/upload-file"
	grok3ModelName          = "grok-3"
	grok3ReasoningModelName = "grok-3-reasoning"
	completionsPath         = "/v1/chat/completions"
	listModelsPath          = "/v1/models"
	defaultBeforePromptText = "For the data below, entries with 'system' are system information, entries with 'assistant' are messages you have previously sent, entries with 'user' are messages sent by the user. You need to respond to the user's last message accordingly based on the corresponding data."
)

// 全局配置变量
var (
	apiToken         *string
	grokCookies      []string
	textBeforePrompt *string
	textAfterPrompt  *string
	keepChat         *bool
	ignoreThinking   *bool
	longTxt          *bool // 控制是否启用长文本上传
	longTxtThreshold int   // 长文本阈值（不需要指针，因为在 main 中解析后固定）
	httpProxy        *string
	cookiesDir       *string
	httpClient       = &http.Client{Timeout: 30 * time.Minute}
	cookie           *string
	port             *uint
	nextCookieIndex  = struct {
		sync.Mutex
		index uint
	}{}
	cookieStatus = struct {
		sync.Mutex
		status map[string]bool // true 表示有效，false 表示失效
	}{
		status: make(map[string]bool),
	}
)

// doRequest 发送 HTTP 请求并返回响应。
func (c *GrokClient) doRequest(method, url string, payload any) (*http.Response, error) {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化请求负载失败: %v", err)
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Grok API 错误: %d %s, 响应体: %s", resp.StatusCode, resp.Status, string(body))
	}
	return resp, nil
}

// uploadMessageAsFile 将消息上传为文件并返回文件 ID。
func (c *GrokClient) uploadMessageAsFile(message string) (*UploadFileResponse, error) {
	content := base64.StdEncoding.EncodeToString([]byte(message))
	payload := UploadFileRequest{
		Content:      content,
		FileMimeType: "text/plain",
		FileName:     uuid.New().String() + ".txt",
	}
	log.Println("正在将消息上传为文件")
	resp, err := c.doRequest(http.MethodPost, uploadFileUrl, payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("上传文件错误: %d %s", resp.StatusCode, resp.Status)
	}
	response := &UploadFileResponse{}
	err = json.Unmarshal(body, response)
	if err != nil || response.FileMetadataId == "" {
		return nil, fmt.Errorf("解析 JSON 错误或 FileMetadataId 为空: %s", string(body))
	}
	return response, nil
}

// sendMessage 向 Grok 3 Web API 发送消息并返回响应体。
func (c *GrokClient) sendMessage(message string, stream bool) (io.ReadCloser, error) {
	fileId := ""
	if (c.enableUpload || c.uploadMessage) && utf8.RuneCountInString(message) >= longTxtThreshold {
		log.Printf("启用 -longtxt，消息长度 %d 超过 %d，正在上传文件", utf8.RuneCountInString(message), longTxtThreshold)
		uploadResp, err := c.uploadMessageAsFile(message)
		if err != nil {
			log.Printf("文件上传失败: %v", err)
			return nil, err
		}
		fileId = uploadResp.FileMetadataId
		log.Printf("文件上传成功，文件ID: %s", fileId)
		message = "请按照附件中的说明进行回复。"
	}

	payload := c.preparePayload(message, fileId)
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

// OpenAIChatCompletionChunk 表示 OpenAI 的流式响应格式。
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

// OpenAIChatCompletion 表示 OpenAI 的非流式响应格式。
type OpenAIChatCompletion struct {
	ID      string                       `json:"id"`
	Object  string                       `json:"object"`
	Created int64                        `json:"created"`
	Model   string                       `json:"model"`
	Choices []OpenAIChatCompletionChoice `json:"choices"`
	Usage   OpenAIChatCompletionUsage    `json:"usage"`
}

// createOpenAIStreamingResponse 返回流式响应处理函数。
func (c *GrokClient) createOpenAIStreamingResponse(grokStream io.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			log.Println("流式传输不支持")
			http.Error(w, "流式传输不支持", http.StatusInternalServerError)
			return
		}

		completionID := "chatcmpl-" + uuid.New().String()
		startChunk := OpenAIChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   c.getModelName(),
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
				Model:   c.getModelName(),
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
			Model:   c.getModelName(),
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

// createOpenAIFullResponse 返回完整响应处理函数。
func (c *GrokClient) createOpenAIFullResponse(grokFull io.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var fullResponse strings.Builder
		c.parseGrok3StreamingJson(grokFull, func(respToken string) {
			fullResponse.WriteString(respToken)
		})

		openAIResponse := c.createOpenAIFullResponseBody(fullResponse.String())
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(openAIResponse); err != nil {
			log.Printf("编码响应错误: %v", err)
			http.Error(w, fmt.Sprintf("编码响应错误: %v", err), http.StatusInternalServerError)
		}
	}
}

// createOpenAIFullResponseBody 创建非流式请求的 OpenAI 响应体。
func (c *GrokClient) createOpenAIFullResponseBody(content string) OpenAIChatCompletion {
	return OpenAIChatCompletion{
		ID:      "chatcmpl-" + uuid.New().String(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   c.getModelName(),
		Choices: []OpenAIChatCompletionChoice{
			{
				Index:        0,
				Message:      OpenAIChatCompletionMessage{Role: "assistant", Content: content},
				FinishReason: "stop",
			},
		},
		Usage: OpenAIChatCompletionUsage{PromptTokens: -1, CompletionTokens: -1, TotalTokens: -1},
	}
}

// mustMarshal 将值序列化为 JSON 字符串。
func mustMarshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// getCookieIndex 返回下一个有效的 cookie 索引
func getCookieIndex(cookies []string, currentIndex uint) uint {
	cookieStatus.Lock()
	defer cookieStatus.Unlock()

	// 检查是否所有 cookie 都失效
	allInvalid := true
	for _, ck := range cookies {
		if cookieStatus.status[ck] {
			allInvalid = false
			break
		}
	}
	if allInvalid {
		log.Println("所有 cookie 已失效，重置状态并重新轮询")
		for _, ck := range cookies {
			cookieStatus.status[ck] = true // 重置所有 cookie 为有效
		}
	}

	// 寻找下一个有效 cookie
	maxAttempts := len(cookies)
	attempts := 0
	index := currentIndex % uint(len(cookies))
	for attempts < maxAttempts {
		if cookieStatus.status[cookies[index]] {
			return index
		}
		index = (index + 1) % uint(len(cookies))
		attempts++
	}
	// 如果没有有效 cookie（理论上不会发生，因为上面已重置），返回 0
	return 0
}

// loadCookiesFromDir 从指定目录加载 cookies。
func loadCookiesFromDir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("cookie 目录不存在: %s", dir)
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
				log.Printf("警告: 读取 cookie 文件 %s 失败: %v", filePath, err)
				continue
			}
			cookie := strings.TrimSpace(string(content))
			if cookie != "" {
				grokCookies = append(grokCookies, cookie)
				log.Printf("从 %s 加载 cookie", filePath)
			}
		}
	}
	return nil
}

// handleChatCompletion 处理 /v1/chat/completions 的 POST 请求。
func handleChatCompletion(w http.ResponseWriter, r *http.Request) {
	log.Printf("来自 %s 的请求，路径: %s", r.RemoteAddr, completionsPath)

	if r.URL.Path != completionsPath || r.Method != http.MethodPost {
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

	var cookie string
	var cookieIndex uint
	if body.GrokCookies != nil {
		if ck, ok := body.GrokCookies.(string); ok {
			cookie = ck
		} else if list, ok := body.GrokCookies.([]any); ok {
			if len(list) > 0 {
				// 将 []any 转换为 []string
				cookieList := make([]string, 0, len(list))
				for _, item := range list {
					if str, ok := item.(string); ok {
						cookieList = append(cookieList, str)
					} else {
						log.Printf("警告: GrokCookies 列表中包含非字符串元素: %v", item)
					}
				}
				if len(cookieList) > 0 {
					cookieIndex = getCookieIndex(cookieList, body.CookieIndex)
					cookie = cookieList[cookieIndex]
				}
			}
		}
	}
	cookie = strings.TrimSpace(cookie)
	if cookie == "" && len(grokCookies) > 0 {
		cookieIndex = getCookieIndex(grokCookies, body.CookieIndex)
		cookie = grokCookies[cookieIndex]
	}
	cookie = strings.TrimSpace(cookie)
	if cookie == "" {
		log.Println("错误: 无 Grok 3 cookie")
		http.Error(w, "错误: 无 Grok 3 cookie", http.StatusBadRequest)
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

	var messageBuilder strings.Builder
	fmt.Fprintln(&messageBuilder, beforePromptText)
	for _, msg := range body.Messages {
		fmt.Fprintf(&messageBuilder, "\n[[%s]]\n", msg.Role)
		messageBuilder.WriteString(msg.Content)
	}
	fmt.Fprintf(&messageBuilder, "\n%s", afterPromptText)

	isReasoning := strings.TrimSpace(body.Model) == grok3ReasoningModelName
	enableSearch := body.EnableSearch > 0
	uploadMessage := body.UploadMessage > 0
	keepConversation := *keepChat
	if body.KeepChat > 0 {
		keepConversation = true
	} else if body.KeepChat == 0 {
		keepConversation = false
	}
	ignoreThink := *ignoreThinking
	if body.IgnoreThinking > 0 {
		ignoreThink = true
	} else if body.IgnoreThinking == 0 {
		ignoreThink = false
	}

	grokClient := NewGrokClient(cookie, isReasoning, enableSearch, uploadMessage, keepConversation, ignoreThink, *longTxt)
	log.Printf("使用索引 %d 的 cookie 请求 Grok 3 Web API", cookieIndex+1)

	respReader, err := grokClient.sendMessage(messageBuilder.String(), body.Stream)
	if err != nil {
		cookieStatus.Lock()
		cookieStatus.status[cookie] = false
		log.Printf("Cookie %d 报错，已标记为失效，原因: %v", cookieIndex+1, err)
		cookieStatus.Unlock()

		cookieIndex = getCookieIndex(grokCookies, cookieIndex+1)
		cookie = grokCookies[cookieIndex]
		grokClient = NewGrokClient(cookie, isReasoning, enableSearch, uploadMessage, keepConversation, ignoreThink, *longTxt)
		log.Printf("切换到索引 %d 的 cookie 重试", cookieIndex+1)

		respReader, err = grokClient.sendMessage(messageBuilder.String(), body.Stream)
		if err != nil {
			log.Printf("重试失败: %v", err)
			http.Error(w, fmt.Sprintf("错误: %v", err), http.StatusInternalServerError)
			return
		}
	}
	defer respReader.Close()

	if body.Stream {
		grokClient.createOpenAIStreamingResponse(respReader)(w, r)
	} else {
		grokClient.createOpenAIFullResponse(respReader)(w, r)
	}
}

// listModels 处理 /v1/models 的 GET 请求。
func listModels(w http.ResponseWriter, r *http.Request) {
	log.Printf("来自 %s 的请求，路径: %s", r.RemoteAddr, listModelsPath)

	if r.URL.Path != listModelsPath || r.Method != http.MethodGet {
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

// main 解析命令行标志并启动服务器。
func main() {
	apiToken = flag.String("token", "", "认证令牌 (GROK3_AUTH_TOKEN)")
	cookie = flag.String("cookie", "", "Grok cookie (GROK3_COOKIE)")
	cookiesDir = flag.String("cookiesDir", "cookies", "包含 cookie.txt 文件的目录")
	textBeforePrompt = flag.String("textBeforePrompt", defaultBeforePromptText, "提示前缀文本")
	textAfterPrompt = flag.String("textAfterPrompt", "", "提示后缀文本")
	keepChat = flag.Bool("keepChat", false, "保留聊天会话")
	ignoreThinking = flag.Bool("ignoreThinking", false, "忽略思考内容")
	longTxt = flag.Bool("longtxt", false, "启用长文本处理，后面可接阈值（如 -longtxt 60000），默认 40000")
	httpProxy = flag.String("httpProxy", "", "HTTP/SOCKS5 代理")
	port = flag.Uint("port", 8180, "服务器端口")
	flag.Parse()

	if *port > 65535 {
		log.Fatalf("服务器端口 %d 超过 65535", *port)
	}

	// 自定义解析 -longtxt 后面的阈值
	longTxtThreshold = 40000 // 默认阈值
	if *longTxt {
		// 检查命令行参数中 -longtxt 后的值
		for i, arg := range os.Args {
			if arg == "-longtxt" && i+1 < len(os.Args) {
				if threshold, err := strconv.Atoi(os.Args[i+1]); err == nil && threshold > 0 {
					longTxtThreshold = threshold
					break
				}
			}
		}
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
		// 先尝试解析为 JSON
		err := json.Unmarshal([]byte(*cookie), &grokCookies)
		if err != nil {
			// 如果不是 JSON，尝试按逗号分割
			if strings.Contains(*cookie, ",") {
				cookieList := strings.Split(*cookie, ",")
				grokCookies = make([]string, 0, len(cookieList))
				for _, c := range cookieList {
					c = strings.TrimSpace(c)
					if c != "" {
						grokCookies = append(grokCookies, c)
					}
				}
			} else {
				// 单个 cookie
				grokCookies = []string{*cookie}
			}
		}
	}

	// 如果未提供 cookie，则从 cookiesDir 加载
	if len(grokCookies) == 0 {
		err := loadCookiesFromDir(*cookiesDir)
		if err != nil {
			log.Printf("警告: 从目录 %s 加载 cookie 失败: %v", *cookiesDir, err)
		}
		if len(grokCookies) == 0 {
			log.Fatal("未找到有效 cookie")
		}
	}

	// 初始化 cookieStatus
	for _, ck := range grokCookies {
		cookieStatus.Lock()
		cookieStatus.status[ck] = true
		cookieStatus.Unlock()
	}

	*httpProxy = strings.TrimSpace(*httpProxy)
	// 配置全局 httpClient
	if *httpProxy != "" {
		proxyURL, err := url.Parse(*httpProxy)
		if err != nil {
			log.Fatalf("解析 HTTP/SOCKS5 代理错误: %v", err)
		}
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
		// 支持系统代理
		httpClient.Transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        10,
			IdleConnTimeout:     600 * time.Second,
			TLSHandshakeTimeout: 20 * time.Second,
		}
	}

	http.HandleFunc(completionsPath, handleChatCompletion)
	http.HandleFunc(listModelsPath, listModels)
	log.Printf("服务器启动于 :%d，长文本处理: %v，阈值: %d，已加载 cookie 数量: %d", *port, *longTxt, longTxtThreshold, len(grokCookies))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
