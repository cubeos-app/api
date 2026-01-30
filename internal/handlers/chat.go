package handlers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// ChatHandler handles AI assistant endpoints
type ChatHandler struct {
	ollamaURL   string
	ollamaModel string
}

// NewChatHandler creates a new chat handler
func NewChatHandler() *ChatHandler {
	return &ChatHandler{
		ollamaURL:   "http://cubeos-ollama:11434",
		ollamaModel: "qwen2.5:0.5b",
	}
}

// Routes returns the router for chat endpoints
func (h *ChatHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/", h.HandleChat)
	r.Post("/stream", h.HandleChatStream)
	r.Get("/status", h.HandleChatStatus)
	r.Post("/pull-model", h.HandlePullModel)
	return r
}

type ChatRequest struct {
	Message string        `json:"message"`
	History []ChatMessage `json:"history,omitempty"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

type ChatStatusResponse struct {
	Available  bool   `json:"available"`
	Model      string `json:"model"`
	ModelReady bool   `json:"model_ready"`
}

// Optimized system prompt for small LLMs (Qwen2.5:0.5b)
// Based on research: 50-150 tokens, explicit format, repeated constraints
// Key changes from original:
// - Reduced from ~300 tokens to ~100 tokens
// - Explicit numbered rules (small models follow these better)
// - No markdown headers (saves tokens, clearer structure)
// - Direct facts section (easier for small models to retrieve)
// - Explicit "don't know" fallback instruction
const systemPrompt = `You are CubeOS Assistant. Answer questions about this home server system.

RULES (follow exactly):
1. Maximum 2-3 sentences per response
2. Use plain text only
3. If unsure, say "I don't have that information"
4. Never invent URLs or passwords

SYSTEM INFO:
- Dashboard: http://cubeos.cube
- Pi-hole DNS: http://pihole.cubeos.cube/admin (password: cubeos)
- Proxy Manager: http://npm.cubeos.cube (cubeos@cubeos.app / cubeos123)
- Logs: http://logs.cubeos.cube
- Containers: http://dockge.cubeos.cube
- WiFi: CubeOS-XXXX network
- IP range: 192.168.42.x

Be direct. No greetings or filler words.`

// HandleChat handles non-streaming chat requests
func (h *ChatHandler) HandleChat(w http.ResponseWriter, r *http.Request) {
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.Message == "" {
		http.Error(w, `{"error":"Message required"}`, http.StatusBadRequest)
		return
	}

	// Build messages array with system prompt
	messages := []map[string]string{
		{"role": "system", "content": systemPrompt},
	}

	// Add history (limited to last 6 messages for small model context)
	historyLimit := 6
	if len(req.History) > historyLimit {
		req.History = req.History[len(req.History)-historyLimit:]
	}
	for _, msg := range req.History {
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	// Add current message
	messages = append(messages, map[string]string{
		"role":    "user",
		"content": req.Message,
	})

	// Optimized parameters for Qwen2.5:0.5b on Raspberry Pi
	// Based on research: lower temp for factual, Qwen-specific top_p/top_k
	ollamaReq := map[string]interface{}{
		"model":    h.ollamaModel,
		"messages": messages,
		"stream":   false,
		"options": map[string]interface{}{
			"temperature":    0.5,  // Lower for factual accuracy (research: 0.3-0.5)
			"top_p":          0.8,  // Qwen documentation recommended
			"top_k":          20,   // Qwen documentation recommended
			"repeat_penalty": 1.1,  // Reduce repetition
			"num_predict":    256,  // Force concise output
			"num_ctx":        2048, // Context window for small model
		},
	}

	body, _ := json.Marshal(ollamaReq)

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(h.ollamaURL+"/api/chat", "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"AI service unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	var ollamaResp struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		http.Error(w, `{"error":"Failed to parse AI response"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ChatResponse{
		Response: ollamaResp.Message.Content,
		Done:     true,
	})
}

// HandleChatStream handles streaming chat requests via SSE
func (h *ChatHandler) HandleChatStream(w http.ResponseWriter, r *http.Request) {
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.Message == "" {
		http.Error(w, `{"error":"Message required"}`, http.StatusBadRequest)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"Streaming not supported"}`, http.StatusInternalServerError)
		return
	}

	// Build messages array
	messages := []map[string]string{
		{"role": "system", "content": systemPrompt},
	}

	// Add limited history
	historyLimit := 6
	if len(req.History) > historyLimit {
		req.History = req.History[len(req.History)-historyLimit:]
	}
	for _, msg := range req.History {
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	messages = append(messages, map[string]string{
		"role":    "user",
		"content": req.Message,
	})

	// Optimized parameters for streaming
	ollamaReq := map[string]interface{}{
		"model":    h.ollamaModel,
		"messages": messages,
		"stream":   true,
		"options": map[string]interface{}{
			"temperature":    0.5,
			"top_p":          0.8,
			"top_k":          20,
			"repeat_penalty": 1.1,
			"num_predict":    256,
			"num_ctx":        2048,
		},
	}

	body, _ := json.Marshal(ollamaReq)

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(h.ollamaURL+"/api/chat", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(w, "data: {\"error\":\"AI service unavailable\"}\n\n")
		flusher.Flush()
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var chunk struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Done bool `json:"done"`
		}

		if err := json.Unmarshal([]byte(line), &chunk); err != nil {
			continue
		}

		if chunk.Message.Content != "" {
			data := map[string]interface{}{
				"content": chunk.Message.Content,
				"done":    chunk.Done,
			}
			jsonData, _ := json.Marshal(data)
			fmt.Fprintf(w, "data: %s\n\n", jsonData)
			flusher.Flush()
		}

		if chunk.Done {
			fmt.Fprintf(w, "data: {\"done\":true}\n\n")
			flusher.Flush()
			break
		}
	}
}

// HandleChatStatus checks if Ollama is available and model is ready
func (h *ChatHandler) HandleChatStatus(w http.ResponseWriter, r *http.Request) {
	status := ChatStatusResponse{
		Available:  false,
		Model:      h.ollamaModel,
		ModelReady: false,
	}

	// Check if Ollama is responding
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(h.ollamaURL + "/api/tags")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
		return
	}
	defer resp.Body.Close()

	status.Available = true

	// Check if model is downloaded
	var tagsResp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err == nil {
		for _, model := range tagsResp.Models {
			if strings.HasPrefix(model.Name, "qwen2.5:0.5b") ||
				strings.HasPrefix(model.Name, h.ollamaModel) {
				status.ModelReady = true
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// HandlePullModel triggers model download
func (h *ChatHandler) HandlePullModel(w http.ResponseWriter, r *http.Request) {
	pullReq := map[string]interface{}{
		"name":   h.ollamaModel,
		"stream": false,
	}

	body, _ := json.Marshal(pullReq)

	client := &http.Client{Timeout: 600 * time.Second} // 10 min for download
	resp, err := client.Post(h.ollamaURL+"/api/pull", "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"Failed to pull model"}`, http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"pulling","model":"` + h.ollamaModel + `"}`))
}
