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

const systemPrompt = `You are CubeOS Assistant, a helpful AI built into CubeOS - an open-source OS for self-hosted ARM64 servers.

## Your Role
- Help users navigate and use CubeOS
- Answer questions about installed services
- Be concise - users are often on mobile

## CubeOS Info
- Dashboard: cubeos.cube or 192.168.42.1
- Pi-hole: pihole.cubeos.cube/admin (password: cubeos)
- NPM: npm.cubeos.cube
- Dockge: dockge.cubeos.cube
- Logs: logs.cubeos.cube

## Guidelines
- Keep responses SHORT (2-3 sentences)
- If unsure, say so
- For live stats, direct users to the Dashboard`

func (h *ChatHandler) HandleChat(w http.ResponseWriter, r *http.Request) {
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Message) == "" {
		http.Error(w, "Message required", http.StatusBadRequest)
		return
	}

	messages := []map[string]string{{"role": "system", "content": systemPrompt}}
	for _, msg := range req.History {
		messages = append(messages, map[string]string{"role": msg.Role, "content": msg.Content})
	}
	messages = append(messages, map[string]string{"role": "user", "content": req.Message})

	ollamaReq := map[string]interface{}{
		"model": h.ollamaModel, "messages": messages, "stream": false,
		"options": map[string]interface{}{"temperature": 0.7, "num_predict": 512},
	}

	reqBody, _ := json.Marshal(ollamaReq)
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(h.ollamaURL+"/api/chat", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, "AI service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	var ollamaResp struct {
		Message struct{ Content string `json:"content"` } `json:"message"`
	}
	json.NewDecoder(resp.Body).Decode(&ollamaResp)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"response": ollamaResp.Message.Content, "model": h.ollamaModel})
}

func (h *ChatHandler) HandleChatStream(w http.ResponseWriter, r *http.Request) {
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	messages := []map[string]string{{"role": "system", "content": systemPrompt}}
	for _, msg := range req.History {
		messages = append(messages, map[string]string{"role": msg.Role, "content": msg.Content})
	}
	messages = append(messages, map[string]string{"role": "user", "content": req.Message})

	ollamaReq := map[string]interface{}{
		"model": h.ollamaModel, "messages": messages, "stream": true,
		"options": map[string]interface{}{"temperature": 0.7, "num_predict": 512},
	}

	reqBody, _ := json.Marshal(ollamaReq)
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(h.ollamaURL+"/api/chat", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, "AI service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, _ := w.(http.Flusher)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var chunk struct {
			Message struct{ Content string `json:"content"` } `json:"message"`
			Done    bool                                      `json:"done"`
		}
		if json.Unmarshal([]byte(line), &chunk) == nil {
			data, _ := json.Marshal(map[string]interface{}{"content": chunk.Message.Content, "done": chunk.Done})
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			if chunk.Done {
				break
			}
		}
	}
}

func (h *ChatHandler) HandleChatStatus(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(h.ollamaURL + "/api/tags")

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"available": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var tags struct{ Models []struct{ Name string `json:"name"` } `json:"models"` }
	json.NewDecoder(resp.Body).Decode(&tags)

	modelReady := false
	for _, m := range tags.Models {
		if strings.Contains(m.Name, "qwen") {
			modelReady = true
			break
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"available": true, "model": h.ollamaModel, "model_ready": modelReady})
}

func (h *ChatHandler) HandlePullModel(w http.ResponseWriter, r *http.Request) {
	pullReq, _ := json.Marshal(map[string]interface{}{"name": h.ollamaModel, "stream": false})
	client := &http.Client{Timeout: 600 * time.Second}
	resp, err := client.Post(h.ollamaURL+"/api/pull", "application/json", bytes.NewReader(pullReq))
	if err != nil {
		http.Error(w, "Failed to pull model", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "pulling", "model": h.ollamaModel})
}
