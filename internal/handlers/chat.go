package handlers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// ChatHandler handles AI assistant endpoints with RAG support
type ChatHandler struct {
	ollamaURL      string
	ollamaModel    string
	embeddingModel string
	chromaURL      string
	collectionName string
}

// NewChatHandler creates a new chat handler with config from environment
func NewChatHandler() *ChatHandler {
	ollamaHost := getEnvDefault("OLLAMA_HOST", "192.168.42.1")
	ollamaPort := getEnvDefault("OLLAMA_PORT", "11434")
	chromaHost := getEnvDefault("CHROMADB_HOST", "192.168.42.1")
	chromaPort := getEnvDefault("CHROMADB_PORT", "8000")
	model := getEnvDefault("OLLAMA_MODEL", "qwen2.5:0.5b")
	embModel := getEnvDefault("EMBEDDING_MODEL", "nomic-embed-text")
	collection := getEnvDefault("CHROMADB_COLLECTION", "cubeos_docs")

	return &ChatHandler{
		ollamaURL:      fmt.Sprintf("http://%s:%s", ollamaHost, ollamaPort),
		ollamaModel:    model,
		embeddingModel: embModel,
		chromaURL:      fmt.Sprintf("http://%s:%s", chromaHost, chromaPort),
		collectionName: collection,
	}
}

// getEnvDefault returns the environment variable value or a default
func getEnvDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
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
	Response string   `json:"response"`
	Done     bool     `json:"done"`
	Sources  []string `json:"sources,omitempty"`
}

type ChatStatusResponse struct {
	Available  bool   `json:"available"`
	Model      string `json:"model"`
	ModelReady bool   `json:"model_ready"`
	RAGEnabled bool   `json:"rag_enabled"`
	DocsCount  int    `json:"docs_count"`
}

// RAG-aware system prompt
const systemPromptTemplate = `You are CubeOS Assistant. Answer questions about this home server system using the provided documentation.

RULES:
1. Use the DOCUMENTATION below to answer questions accurately
2. Maximum 2-3 sentences per response
3. If the documentation doesn't cover the topic, say "I don't have that information in my documentation"
4. Never invent URLs, passwords, or commands not in the documentation
5. Be direct and helpful

DOCUMENTATION:
%s

SYSTEM INFO (always available):
- Dashboard: http://cubeos.cube
- WiFi: CubeOS-XXXX network
- IP range: 192.168.42.x

Answer the user's question based on the documentation above.`

// Fallback prompt when RAG is unavailable
const fallbackSystemPrompt = `You are CubeOS Assistant. Answer questions about this home server system.

RULES:
1. Maximum 2-3 sentences per response
2. If unsure, say "I don't have that information"
3. Never invent URLs or passwords

SYSTEM INFO:
- Dashboard: http://cubeos.cube
- Pi-hole DNS: http://pihole.cubeos.cube/admin
- Proxy Manager: http://npm.cubeos.cube
- Logs: http://logs.cubeos.cube
- Containers: http://dockge.cubeos.cube
- WiFi: CubeOS-XXXX network
- IP range: 192.168.42.x

Be direct. No greetings or filler words.`

// GitHub base URL for documentation links
const docsBaseURL = "https://github.com/cubeos-app/docs/blob/main/"

// getRelevantDocs queries ChromaDB for documents relevant to the query
func (h *ChatHandler) getRelevantDocs(query string, nResults int) ([]string, []string, error) {
	// Generate embedding for the query
	embedding, err := h.getEmbedding(query)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate query embedding: %w", err)
	}

	// Get collection ID
	collectionID, err := h.getCollectionID()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get collection: %w", err)
	}

	// Query ChromaDB
	queryURL := fmt.Sprintf("%s/api/v2/tenants/default_tenant/databases/default_database/collections/%s/query",
		h.chromaURL, collectionID)

	queryReq := map[string]interface{}{
		"query_embeddings": [][]float32{embedding},
		"n_results":        nResults,
		"include":          []string{"documents", "metadatas"},
	}
	body, _ := json.Marshal(queryReq)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(queryURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("ChromaDB query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("ChromaDB query returned status %d", resp.StatusCode)
	}

	var result struct {
		Documents [][]string            `json:"documents"`
		Metadatas [][]map[string]string `json:"metadatas"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("failed to decode ChromaDB response: %w", err)
	}

	if len(result.Documents) == 0 || len(result.Documents[0]) == 0 {
		return nil, nil, nil
	}

	// Extract documents and sources (convert to GitHub URLs)
	docs := result.Documents[0]
	var sources []string
	if len(result.Metadatas) > 0 {
		for _, meta := range result.Metadatas[0] {
			if source, ok := meta["source"]; ok {
				// Convert to GitHub URL
				githubURL := docsBaseURL + source
				// Deduplicate sources
				found := false
				for _, s := range sources {
					if s == githubURL {
						found = true
						break
					}
				}
				if !found {
					sources = append(sources, githubURL)
				}
			}
		}
	}

	return docs, sources, nil
}

// getEmbedding generates an embedding for text using Ollama
func (h *ChatHandler) getEmbedding(text string) ([]float32, error) {
	reqBody := map[string]string{
		"model":  h.embeddingModel,
		"prompt": text,
	}
	body, _ := json.Marshal(reqBody)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(h.ollamaURL+"/api/embeddings", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("embedding request failed with status %d", resp.StatusCode)
	}

	var result struct {
		Embedding []float32 `json:"embedding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Embedding, nil
}

// getCollectionID retrieves the ChromaDB collection ID
func (h *ChatHandler) getCollectionID() (string, error) {
	url := fmt.Sprintf("%s/api/v2/tenants/default_tenant/databases/default_database/collections/%s",
		h.chromaURL, h.collectionName)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("collection not found (status %d)", resp.StatusCode)
	}

	var collection struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&collection); err != nil {
		return "", err
	}

	return collection.ID, nil
}

// getDocsCount returns the number of documents in ChromaDB
func (h *ChatHandler) getDocsCount() int {
	collectionID, err := h.getCollectionID()
	if err != nil {
		return 0
	}

	url := fmt.Sprintf("%s/api/v2/tenants/default_tenant/databases/default_database/collections/%s/count",
		h.chromaURL, collectionID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	var count int
	if err := json.NewDecoder(resp.Body).Decode(&count); err != nil {
		return 0
	}

	return count
}

// buildSystemPrompt creates a system prompt with RAG context
func (h *ChatHandler) buildSystemPrompt(query string) (string, []string) {
	// Try to get relevant documents (reduced to 2 for more focused responses)
	docs, sources, err := h.getRelevantDocs(query, 2)
	if err != nil || len(docs) == 0 {
		// Fallback to static prompt if RAG fails
		return fallbackSystemPrompt, nil
	}

	// Combine documents into context
	context := strings.Join(docs, "\n\n---\n\n")

	// Truncate if too long (reduced to 1000 chars for more concise responses)
	if len(context) > 1000 {
		context = context[:1000] + "..."
	}

	return fmt.Sprintf(systemPromptTemplate, context), sources
}

// HandleChat handles non-streaming chat requests with RAG
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

	// Build RAG-enhanced system prompt
	systemPrompt, sources := h.buildSystemPrompt(req.Message)

	// Build messages array
	messages := []map[string]string{
		{"role": "system", "content": systemPrompt},
	}

	// Add history (limited to last 4 messages for small model context)
	historyLimit := 4
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

	// Optimized parameters for Qwen2.5:0.5b
	ollamaReq := map[string]interface{}{
		"model":    h.ollamaModel,
		"messages": messages,
		"stream":   false,
		"options": map[string]interface{}{
			"temperature":    0.3, // Lower for factual RAG responses
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
		Sources:  sources,
	})
}

// HandleChatStream handles streaming chat requests via SSE with RAG
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

	// Build RAG-enhanced system prompt
	systemPrompt, sources := h.buildSystemPrompt(req.Message)

	// Send sources first if available
	if len(sources) > 0 {
		sourcesData, _ := json.Marshal(map[string]interface{}{
			"sources": sources,
		})
		fmt.Fprintf(w, "data: %s\n\n", sourcesData)
		flusher.Flush()
	}

	// Build messages array
	messages := []map[string]string{
		{"role": "system", "content": systemPrompt},
	}

	// Add limited history
	historyLimit := 4
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
			"temperature":    0.3,
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

// HandleChatStatus checks if Ollama and RAG are available
func (h *ChatHandler) HandleChatStatus(w http.ResponseWriter, r *http.Request) {
	status := ChatStatusResponse{
		Available:  false,
		Model:      h.ollamaModel,
		ModelReady: false,
		RAGEnabled: false,
		DocsCount:  0,
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

	// Check RAG availability
	docsCount := h.getDocsCount()
	if docsCount > 0 {
		status.RAGEnabled = true
		status.DocsCount = docsCount
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

	client := &http.Client{Timeout: 600 * time.Second}
	resp, err := client.Post(h.ollamaURL+"/api/pull", "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"Failed to pull model"}`, http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"pulling","model":"` + h.ollamaModel + `"}`))
}
