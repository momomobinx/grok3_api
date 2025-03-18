package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
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

	"github.com/andybalholm/brotli"
	"github.com/google/uuid"
)

// GrokClient defines a client for interacting with the Grok 3 Web API.
type GrokClient struct {
	headers        map[string]string // HTTP headers for API requests
	isReasoning    bool              // Flag for using reasoning model
	enableSearch   bool              // Flag for searching in the Web
	keepChat       bool              // Flag to preserve chat history
	ignoreThinking bool              // Flag to exclude thinking tokens in responses
}

// NewGrokClient creates a new instance of GrokClient with the provided cookies and configuration flags.
func NewGrokClient(cookie string, isReasoning bool, enableSearch bool, keepChat bool, ignoreThinking bool) *GrokClient {
	return &GrokClient{
		headers: map[string]string{
			"accept":             "*/*",
			"accept-encoding":    "gzip, deflate, br, zstd",
			"accept-language":    "accept-language: zh-CN,zh;q=0.9",
			"content-type":       "application/json",
			"authority":          "grok.com",
			"origin":             "https://grok.com",
			"dnt":                "1",
			"priority":           "u=1, i",
			"referer":            "https://grok.com/",
			"sec-ch-ua":          `"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"Windows"`,
			"sec-fetch-dest":     "empty",
			"sec-fetch-mode":     "cors",
			"sec-fetch-site":     "same-origin",
			"sec-gpc":            "1",
			"user-agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			"cookie":             cookie,
		},
		isReasoning:    isReasoning,
		enableSearch:   enableSearch,
		keepChat:       keepChat,
		ignoreThinking: ignoreThinking,
	}
}

// ToolOverrides defines the tool overrides for the Grok 3 Web API.
type ToolOverrides struct {
	WebSearch bool `json:"webSearch"`
}

// preparePayload constructs the request payload for the Grok 3 Web API.
func (c *GrokClient) preparePayload(message string, fileAttachments []string) map[string]any {
	toolOverrides := ToolOverrides{WebSearch: c.enableSearch}
	return map[string]any{
		"message":         message,
		"modelName":       "grok-3",
		"isReasoning":     c.isReasoning,
		"temporary":       !c.keepChat,
		"fileAttachments": fileAttachments,
		"toolOverrides":   toolOverrides,
	}
}

// getModelName returns the appropriate model name based on the isReasoning flag.
func (c *GrokClient) getModelName() string {
	if c.isReasoning {
		return "grok-3-reasoning"
	}
	return "grok-3"
}

// RequestBody represents the structure of the JSON body for /v1/chat/completions.
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
	KeepChat       int  `json:"keepChat,omitempty"`
	IgnoreThinking int  `json:"ignoreThinking,omitempty"`
}

// ResponseToken represents a single token response from the Grok 3 Web API.
type ResponseToken struct {
	Result struct {
		Response struct {
			Token      string `json:"token"`
			IsThinking bool   `json:"isThinking"`
		} `json:"response"`
	} `json:"result"`
}

// ModelData represents model metadata for OpenAI-compatible response.
type ModelData struct {
	Id       string `json:"id"`
	Object   string `json:"object"`
	Owned_by string `json:"owned_by"`
}

// ModelList contains available models for OpenAI-compatible endpoint.
type ModelList struct {
	Object string      `json:"object"`
	Data   []ModelData `json:"data"`
}

// UploadFileRequest represents the request for uploading a file.
type UploadFileRequest struct {
	Content      string `json:"content"`
	FileMimeType string `json:"fileMimeType"`
	FileName     string `json:"fileName"`
}

// UploadFileResponse represents the response for uploading a file.
type UploadFileResponse struct {
	FileMetadataId string `json:"fileMetadataId"`
}

const (
	newChatUrl    = "https://grok.com/rest/app-chat/conversations/new" // Endpoint for creating new conversations
	uploadFileUrl = "https://grok.com/rest/app-chat/upload-file"       // Endpoint for uploading files

	grok3ModelName          = "grok-3"
	grok3ReasoningModelName = "grok-3-reasoning"
	completionsPath         = "/v1/chat/completions"
	listModelsPath          = "/v1/models"
)

// Global configuration variables.
var (
	apiToken        *string
	grokCookies     []string
	keepChat        *bool
	ignoreThinking  *bool
	httpProxy       *string
	cookiesDir      *string
	longTxt         *bool
	httpClient      = &http.Client{Timeout: 30 * time.Minute}
	nextCookieIndex = struct {
		sync.Mutex
		index uint
	}{}
)

// sendMessage sends a message to the Grok 3 Web API and returns the response body.
func (c *GrokClient) sendMessage(message string, stream bool, fileAttachments []string) (io.ReadCloser, error) {
	payload := c.preparePayload(message, fileAttachments)
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonPayload))
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
		respBody, err := decompressBody(resp)
		if err != nil {
			return nil, err
		}
		defer respBody.Close()
		body, err := io.ReadAll(respBody)
		if err != nil {
			return nil, fmt.Errorf("the Grok API error: %s", resp.Status)
		}
		return nil, fmt.Errorf("the Grok API error: %s, response body: %s", resp.Status, string(body)[:128])
	}

	return resp, nil
}

func (c *GrokClient) uploadMessageAsFile(message string) (*UploadFileResponse, error) {
	content := base64.StdEncoding.EncodeToString([]byte(message))
	payload := UploadFileRequest{
		Content:      content,
		FileMimeType: "text/plain",
		FileName:     uuid.New().String() + ".txt",
	}
	log.Println("Uploading the message as a file")
	resp, err := c.doRequest(http.MethodPost, uploadFileUrl, payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := decompressBody(resp)
	if err != nil {
		return nil, err
	}
	defer respBody.Close()
	body, err := io.ReadAll(respBody)
	if err != nil {
		return nil, fmt.Errorf("uploading file error: %d %s", resp.StatusCode, resp.Status)
	}
	response := &UploadFileResponse{}
	err = json.Unmarshal(body, response)
	if err != nil {
		return nil, fmt.Errorf("parsing json error: %s", string(body))
	}
	if response.FileMetadataId == "" {
		return nil, fmt.Errorf("uploading file error: empty `FileMetadataId`")
	}

	return response, nil
}

// sendMessage sends a message to the Grok 3 Web API and returns the response body as an io.ReadCloser.
// If stream is true, it returns the streaming response; otherwise, it reads the entire response.
func (c *GrokClient) sendMessage(message string) (*http.Response, error) {
	fileId := ""
	if c.uploadMessage || (len(message) > int(*charsLimit) && utf8.RuneCountInString(message) > int(*charsLimit)) {
		uploadResp, err := c.uploadMessageAsFile(message)
		if err != nil {
			return nil, err
		}
		fileId = uploadResp.FileMetadataId
		message = defaultUploadMessagePrompt
	}

	payload := c.preparePayload(message, fileId)
	resp, err := c.doRequest(http.MethodPost, newChatUrl, payload)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// OpenAIChatCompletionMessage defines the message structure for OpenAI responses.
type OpenAIChatCompletionMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIChatCompletionChunkChoice defines a choice in a streaming chunk.
type OpenAIChatCompletionChunkChoice struct {
	Index        int                         `json:"index"`
	Delta        OpenAIChatCompletionMessage `json:"delta"`
	FinishReason string                      `json:"finish_reason"`
}

// OpenAIChatCompletionChunk represents the streaming response format.
type OpenAIChatCompletionChunk struct {
	ID      string                            `json:"id"`
	Object  string                            `json:"object"`
	Created int64                             `json:"created"`
	Model   string                            `json:"model"`
	Choices []OpenAIChatCompletionChunkChoice `json:"choices"`
}

// OpenAIChatCompletionChoice defines a choice in a full response.
type OpenAIChatCompletionChoice struct {
	Index        int                         `json:"index"`
	Message      OpenAIChatCompletionMessage `json:"message"`
	FinishReason string                      `json:"finish_reason"`
}

// OpenAIChatCompletionUsage tracks token usage.
type OpenAIChatCompletionUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// OpenAIChatCompletion represents the non-streaming response format.
type OpenAIChatCompletion struct {
	ID      string                       `json:"id"`
	Object  string                       `json:"object"`
	Created int64                        `json:"created"`
	Model   string                       `json:"model"`
	Choices []OpenAIChatCompletionChoice `json:"choices"`
	Usage   OpenAIChatCompletionUsage    `json:"usage"`
}

// parseGrok3StreamingJson parses the streaming response from Grok 3.
func (c *GrokClient) parseGrok3StreamingJson(stream io.Reader, handler func(respToken string)) {
	isThinking := false
	decoder := json.NewDecoder(stream)
	for {
		var token ResponseToken
		err := decoder.Decode(&token)
		if err == io.EOF {
			break
		} else if err != nil {
			log.Printf("Parsing json error: %v", err)
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

// CreateOpenAIStreamingResponse converts Grok 3 streaming response to OpenAI format.
func (c *GrokClient) CreateOpenAIStreamingResponse(grokStream io.Reader) http.HandlerFunc {
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

		c.parseGrok3StreamingJson(grokStream, func(respToken string) {
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
		})

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

// CreateOpenAIFullResponse converts Grok 3 full response to OpenAI format.
func (c *GrokClient) CreateOpenAIFullResponse(grokFull io.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var fullResponse strings.Builder
		c.parseGrok3StreamingJson(grokFull, func(respToken string) {
			fullResponse.WriteString(respToken)
		})

		openAIResponse := c.createOpenAIFullResponseBody(fullResponse.String())
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(openAIResponse); err != nil {
			log.Printf("Encoding response error: %v", err)
			http.Error(w, fmt.Sprintf("Encoding response error: %v", err), http.StatusInternalServerError)
			return
		}
	}
}

// createOpenAIFullResponseBody creates the OpenAI response body for non-streaming requests.
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

// mustMarshal serializes a value to JSON, panicking on error.
func mustMarshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// getCookieIndex selects the next cookie index in a round-robin fashion.
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

// createMessagesAttachment creates a text file with message history.
func createMessagesAttachment(messages []struct {
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
		return "", fmt.Errorf("failed to create file: %v", err)
	}
	defer tempFile.Close()

	if _, err := tempFile.WriteString(builder.String()); err != nil {
		return "", fmt.Errorf("failed to write to file: %v", err)
	}

	return tempFile.Name(), nil
}

// handleChatCompletion handles POST requests to /v1/chat/completions.
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

	body := RequestBody{EnableSearch: -1, KeepChat: -1, IgnoreThinking: -1}
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

	var fileAttachments []string
	if *longTxt && len(messages) > 1 {
		tempFilePath, err := createMessagesAttachment(messages)
		if err != nil {
			log.Printf("Error creating message attachment: %v", err)
			http.Error(w, fmt.Sprintf("Error creating message attachment: %v", err), http.StatusInternalServerError)
			return
		}
		fileAttachments = append(fileAttachments, tempFilePath)
		defer os.Remove(tempFilePath)
		log.Printf("Created message attachment with %d messages at %s", len(messages), tempFilePath)
	}

	isReasoning := false
	if strings.TrimSpace(body.Model) == grok3ReasoningModelName {
		isReasoning = true
	}

	enableSearch := false
	if body.EnableSearch > 0 {
		enableSearch = true
	}

	keepConversation := false
	if body.KeepChat > 0 {
		keepConversation = true
	} else if body.KeepChat < 0 {
		keepConversation = *keepChat
	}

	ignoreThink := false
	if body.IgnoreThinking > 0 {
		ignoreThink = true
	} else if body.IgnoreThinking < 0 {
		ignoreThink = *ignoreThinking
	}

	grokClient := NewGrokClient(cookie, isReasoning, enableSearch, keepConversation, ignoreThink)
	log.Printf("Use the cookie with index %d to request Grok 3 Web API", cookieIndex+1)

	respReader, err := grokClient.sendMessage(messageJson.String(), body.Stream, fileAttachments)
	if err != nil {
		log.Printf("Error: %v", err)
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	respBody, err := decompressBody(resp)
	if err != nil {
		log.Printf("Error: %v", err)
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}
	defer respBody.Close()

	if body.Stream {
		grokClient.CreateOpenAIStreamingResponse(respReader)(w, r)
	} else {
		grokClient.CreateOpenAIFullResponse(respReader)(w, r)
	}
	_, _ = io.ReadAll(respBody)
}

// listModels handles GET requests to /v1/models.
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
			{
				Id:       grok3ModelName,
				Object:   "model",
				Owned_by: "xAI",
			},
			{
				Id:       grok3ReasoningModelName,
				Object:   "model",
				Owned_by: "xAI",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(list); err != nil {
		log.Printf("Encoding response error: %v", err)
		http.Error(w, fmt.Sprintf("Encoding response error: %v", err), http.StatusInternalServerError)
		return
	}
}

// loadCookiesFromDir loads cookies from the specified directory.
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

// main sets up the HTTP server and starts listening.
func main() {
	apiToken = flag.String("token", "", "Authentication token (GROK3_AUTH_TOKEN)")
	cookie := flag.String("cookie", "", "Grok cookie (GROK3_COOKIE)")
	cookiesDir = flag.String("cookiesDir", "cookies", "Directory containing cookie.txt files")
	keepChat = flag.Bool("keepChat", false, "Retain the chat conversation")
	ignoreThinking = flag.Bool("ignoreThinking", false, "Ignore thinking content")
	httpProxy = flag.String("httpProxy", "", "HTTP/SOCKS5 proxy")
	longTxt = flag.Bool("longtxt", false, "Enable uploading long conversations as text file")
	port := flag.Uint("port", 8180, "Server port")
	flag.Parse()

	if *port > 65535 {
		log.Fatalf("Server port %d is greater than 65535", *port)
	}

	*apiToken = strings.TrimSpace(*apiToken)
	if *apiToken == "" {
		*apiToken = strings.TrimSpace(os.Getenv("GROK3_AUTH_TOKEN"))
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
	// Get cookies from `cookieFile`
	if *cookieFile != "" {
		file, err := os.Open(*cookieFile)
		if err != nil {
			log.Fatalf("Open file %s error: %v", *cookieFile, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			c := strings.TrimSpace(scanner.Text())
			if c != "" {
				grokCookies = append(grokCookies, c)
			}
		}
		if err = scanner.Err(); err != nil {
			log.Fatalf("Reading file %s error: %v", *cookieFile, err)
		}
	}

	if len(grokCookies) == 0 {
		err := loadCookiesFromDir(*cookiesDir)
		if err != nil {
			log.Printf("Warning: Failed to load cookies from directory %s: %v", *cookiesDir, err)
		}
		if len(grokCookies) == 0 {
			log.Fatal("No valid cookies found")
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
			log.Fatalf("Parsing HTTP/SOCKS5 proxy error: %v", err)
		}
	}

	http.HandleFunc(completionsPath, handleChatCompletion)
	http.HandleFunc(listModelsPath, listModels)
	log.Printf("Server starting on :%d with %d cookies loaded, longtxt enabled: %v", *port, len(grokCookies), *longTxt)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
