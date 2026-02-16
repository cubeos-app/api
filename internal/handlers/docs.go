package handlers

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
)

// DocsHandler handles documentation endpoints
type DocsHandler struct {
	docsPath string
}

// NewDocsHandler creates a new docs handler
func NewDocsHandler() *DocsHandler {
	docsPath := os.Getenv("DOCS_PATH")
	if docsPath == "" {
		docsPath = "/cubeos/docs"
	}
	return &DocsHandler{
		docsPath: docsPath,
	}
}

// Routes returns the router for docs endpoints
func (h *DocsHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.ListDocs)
	r.Get("/tree", h.GetDocsTree)
	r.Get("/status", h.GetDocsStatus)
	r.Get("/search", h.SearchDocs)
	r.Get("/*", h.GetDoc)
	return r
}

// ---------------------------------------------------------------------------
// Built-in fallback documentation (served when /cubeos/docs/ is empty)
// ---------------------------------------------------------------------------

const builtinGettingStartedContent = `# Getting Started with CubeOS

Welcome to CubeOS — your self-hosted server operating system for Raspberry Pi.

## Quick Links

- **Dashboard:** http://cubeos.cube
- **API Docs:** http://api.cubeos.cube/api/v1/swagger/index.html
- **Pi-hole DNS:** http://pihole.cubeos.cube
- **Logs (Dozzle):** http://dozzle.cubeos.cube

## First Steps

1. Connect to the CubeOS WiFi access point
2. Open the dashboard at http://cubeos.cube
3. Complete the Setup Wizard to configure your device
4. Install additional services from the App Store

## Network Modes

- **Offline** — Access Point only, air-gapped operation
- **Online (Ethernet)** — AP + internet via Ethernet cable
- **Online (WiFi)** — AP + internet via USB WiFi dongle

## Documentation

Full documentation is available online at https://docs.cubeos.app.

Offline documentation files will appear here automatically when they are
available in /cubeos/docs on the device.
`

var builtinDocsList = []DocFile{
	{
		Path:  "getting-started",
		Name:  "getting-started.md",
		Title: "Getting Started with CubeOS",
	},
}

var builtinDocsContent = map[string]DocContent{
	"getting-started": {
		Path:    "getting-started",
		Title:   "Getting Started with CubeOS",
		Content: builtinGettingStartedContent,
	},
}

// hasDocsOnDisk checks whether /cubeos/docs/ contains any .md files
func (h *DocsHandler) hasDocsOnDisk() bool {
	count := 0
	filepath.WalkDir(h.docsPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".md") &&
			!strings.HasPrefix(d.Name(), ".") {
			count++
			return filepath.SkipAll // found at least one, stop walking
		}
		return nil
	})
	return count > 0
}

// DocFile represents a documentation file
type DocFile struct {
	Path     string    `json:"path"`
	Name     string    `json:"name"`
	Title    string    `json:"title"`
	IsDir    bool      `json:"is_dir,omitempty"`
	Children []DocFile `json:"children,omitempty"`
}

// DocContent represents a document with its content
type DocContent struct {
	Path    string `json:"path"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

// ListDocs godoc
// @Summary List all documentation files
// @Description Returns a flat list of all markdown documentation files sorted by path. Titles are extracted from the first H1 heading in each file. Returns built-in fallback docs when /cubeos/docs/ is empty.
// @Tags Docs
// @Produce json
// @Security BearerAuth
// @Success 200 {array} DocFile "Array of documentation files"
// @Failure 500 {object} ErrorResponse "Failed to list docs"
// @Router /documentation [get]
func (h *DocsHandler) ListDocs(w http.ResponseWriter, r *http.Request) {
	var docs []DocFile

	err := filepath.WalkDir(h.docsPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden files and directories
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Only include markdown files
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			relPath, _ := filepath.Rel(h.docsPath, path)
			// Remove .md extension for cleaner URLs
			urlPath := strings.TrimSuffix(relPath, ".md")

			title := extractTitleFromFile(path)
			if title == "" {
				title = strings.TrimSuffix(d.Name(), ".md")
			}

			docs = append(docs, DocFile{
				Path:  urlPath,
				Name:  d.Name(),
				Title: title,
			})
		}

		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		http.Error(w, `{"error":"Failed to list docs"}`, http.StatusInternalServerError)
		return
	}

	// B45: Serve built-in fallback when directory is empty
	if len(docs) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(builtinDocsList)
		return
	}

	// Sort by path
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].Path < docs[j].Path
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docs)
}

// GetDocsTree godoc
// @Summary Get documentation tree
// @Description Returns documentation files as a hierarchical tree structure with directories and nested children. Directories are sorted before files. Returns built-in fallback docs when /cubeos/docs/ is empty.
// @Tags Docs
// @Produce json
// @Security BearerAuth
// @Success 200 {array} DocFile "Tree of documentation files with nested children"
// @Router /documentation/tree [get]
func (h *DocsHandler) GetDocsTree(w http.ResponseWriter, r *http.Request) {
	tree := buildDocTree(h.docsPath, h.docsPath)

	// B45: Serve built-in fallback when directory is empty
	if len(tree) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(builtinDocsList)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tree)
}

// buildDocTree recursively builds a tree of documentation files
func buildDocTree(basePath, currentPath string) []DocFile {
	var items []DocFile

	entries, err := os.ReadDir(currentPath)
	if err != nil {
		return items
	}

	for _, entry := range entries {
		// Skip hidden files
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		fullPath := filepath.Join(currentPath, entry.Name())
		relPath, _ := filepath.Rel(basePath, fullPath)

		if entry.IsDir() {
			children := buildDocTree(basePath, fullPath)
			if len(children) > 0 {
				items = append(items, DocFile{
					Path:     relPath,
					Name:     entry.Name(),
					Title:    formatDirName(entry.Name()),
					IsDir:    true,
					Children: children,
				})
			}
		} else if strings.HasSuffix(strings.ToLower(entry.Name()), ".md") {
			urlPath := strings.TrimSuffix(relPath, ".md")
			title := extractTitleFromFile(fullPath)
			if title == "" {
				title = strings.TrimSuffix(entry.Name(), ".md")
			}

			items = append(items, DocFile{
				Path:  urlPath,
				Name:  entry.Name(),
				Title: title,
			})
		}
	}

	// Sort: directories first, then files, alphabetically
	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return items[i].Name < items[j].Name
	})

	return items
}

// GetDoc godoc
// @Summary Get documentation file content
// @Description Returns the content of a specific markdown documentation file. The .md extension is optional in the path. Returns README.md if no path is specified. Falls back to built-in docs when file not found on disk.
// @Tags Docs
// @Produce json
// @Security BearerAuth
// @Param path path string false "Document path (without .md extension)"
// @Success 200 {object} DocContent "Document content with title and path"
// @Failure 400 {object} ErrorResponse "Invalid path (directory traversal attempt)"
// @Failure 404 {object} ErrorResponse "Document not found"
// @Failure 500 {object} ErrorResponse "Failed to read document"
// @Router /documentation/{path} [get]
func (h *DocsHandler) GetDoc(w http.ResponseWriter, r *http.Request) {
	// Get the path from URL (everything after /api/v1/docs/)
	docPath := chi.URLParam(r, "*")
	if docPath == "" {
		docPath = "README"
	}

	// Add .md extension if not present
	if !strings.HasSuffix(docPath, ".md") {
		docPath = docPath + ".md"
	}

	// Construct full path and prevent directory traversal
	fullPath := filepath.Join(h.docsPath, filepath.Clean(docPath))
	if !strings.HasPrefix(fullPath, h.docsPath) {
		http.Error(w, `{"error":"Invalid path"}`, http.StatusBadRequest)
		return
	}

	// Read the file
	content, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			// B45: Check built-in fallback docs before returning 404
			cleanPath := strings.TrimSuffix(docPath, ".md")
			if builtin, ok := builtinDocsContent[cleanPath]; ok {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(builtin)
				return
			}
			http.Error(w, `{"error":"Document not found"}`, http.StatusNotFound)
		} else {
			http.Error(w, `{"error":"Failed to read document"}`, http.StatusInternalServerError)
		}
		return
	}

	title := extractTitle(string(content))
	if title == "" {
		title = strings.TrimSuffix(filepath.Base(docPath), ".md")
	}

	// Return as JSON with content
	doc := DocContent{
		Path:    strings.TrimSuffix(docPath, ".md"),
		Title:   title,
		Content: string(content),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

// SearchDocs godoc
// @Summary Search documentation
// @Description Searches documentation content for the given query (case-insensitive). Returns matching files with their paths and titles.
// @Tags Docs
// @Produce json
// @Security BearerAuth
// @Param q query string true "Search query"
// @Success 200 {array} DocFile "Array of matching documentation files"
// @Failure 400 {object} ErrorResponse "Query parameter 'q' required"
// @Router /documentation/search [get]
func (h *DocsHandler) SearchDocs(w http.ResponseWriter, r *http.Request) {
	query := strings.ToLower(r.URL.Query().Get("q"))
	if query == "" {
		http.Error(w, `{"error":"Query parameter 'q' required"}`, http.StatusBadRequest)
		return
	}

	var results []DocFile

	filepath.WalkDir(h.docsPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		if strings.HasPrefix(d.Name(), ".") || !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Search in content (case-insensitive)
		if strings.Contains(strings.ToLower(string(content)), query) {
			relPath, _ := filepath.Rel(h.docsPath, path)
			urlPath := strings.TrimSuffix(relPath, ".md")
			title := extractTitle(string(content))
			if title == "" {
				title = strings.TrimSuffix(d.Name(), ".md")
			}

			results = append(results, DocFile{
				Path:  urlPath,
				Name:  d.Name(),
				Title: title,
			})
		}

		return nil
	})

	// B45: Search built-in docs as well when directory is empty
	if len(results) == 0 && !h.hasDocsOnDisk() {
		for _, doc := range builtinDocsContent {
			if strings.Contains(strings.ToLower(doc.Content), query) ||
				strings.Contains(strings.ToLower(doc.Title), query) {
				results = append(results, DocFile{
					Path:  doc.Path,
					Name:  doc.Path + ".md",
					Title: doc.Title,
				})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// DocStatus represents the documentation service status
type DocStatus struct {
	Mode          string `json:"mode"`
	DocsAvailable bool   `json:"docs_available"`
	DocCount      int    `json:"doc_count"`
}

// GetDocsStatus godoc
// @Summary Get documentation status
// @Description Returns the current status of the documentation system, including whether docs are available on disk and the mode of operation.
// @Tags Docs
// @Produce json
// @Security BearerAuth
// @Success 200 {object} DocStatus "Documentation status"
// @Router /documentation/status [get]
func (h *DocsHandler) GetDocsStatus(w http.ResponseWriter, r *http.Request) {
	docCount := 0
	filepath.WalkDir(h.docsPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".md") &&
			!strings.HasPrefix(d.Name(), ".") {
			docCount++
		}
		return nil
	})

	mode := "builtin"
	if docCount > 0 {
		mode = "filesystem"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DocStatus{
		Mode:          mode,
		DocsAvailable: docCount > 0,
		DocCount:      docCount,
	})
}

// extractTitle extracts the first H1 heading from markdown content
func extractTitle(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimPrefix(line, "# ")
		}
	}
	return ""
}

// extractTitleFromFile reads a file and extracts its title
func extractTitleFromFile(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return extractTitle(string(content))
}

// formatDirName converts directory names to readable titles
func formatDirName(name string) string {
	// Replace hyphens and underscores with spaces
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.ReplaceAll(name, "_", " ")
	// Capitalize first letter
	if len(name) > 0 {
		return strings.ToUpper(name[:1]) + name[1:]
	}
	return name
}
