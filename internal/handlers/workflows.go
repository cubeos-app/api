// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/flowengine"
)

// WorkflowsHandler exposes read-only visibility into FlowEngine workflow runs.
type WorkflowsHandler struct {
	store *flowengine.WorkflowStore
}

// NewWorkflowsHandler creates a new WorkflowsHandler.
func NewWorkflowsHandler(store *flowengine.WorkflowStore) *WorkflowsHandler {
	return &WorkflowsHandler{store: store}
}

// Routes returns the router for workflow visibility endpoints.
func (h *WorkflowsHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.ListWorkflows)
	r.Get("/{id}", h.GetWorkflow)
	return r
}

// ListWorkflows godoc
// @Summary List workflow runs
// @Description Returns recent workflow runs with optional filtering by type and state
// @Tags Workflows
// @Produce json
// @Security BearerAuth
// @Param type query string false "Filter by workflow type (app_install, app_remove, appstore_install, appstore_remove)"
// @Param state query string false "Filter by state (pending, running, completed, failed, compensating, compensated)"
// @Param limit query int false "Maximum number of results (default 50)"
// @Param offset query int false "Pagination offset (default 0)"
// @Success 200 {object} map[string]interface{} "List of workflow runs"
// @Failure 500 {object} ErrorResponse "Failed to list workflows"
// @Router /workflows [get]
func (h *WorkflowsHandler) ListWorkflows(w http.ResponseWriter, r *http.Request) {
	filter := flowengine.ListWorkflowsFilter{
		WorkflowType: r.URL.Query().Get("type"),
		State:        r.URL.Query().Get("state"),
		Limit:        50,
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			filter.Limit = n
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			filter.Offset = n
		}
	}

	workflows, err := h.store.ListWorkflows(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list workflows: "+err.Error())
		return
	}

	if workflows == nil {
		workflows = []flowengine.WorkflowRun{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflows": workflows,
		"count":     len(workflows),
	})
}

// GetWorkflow godoc
// @Summary Get a workflow run
// @Description Returns a single workflow run with its steps
// @Tags Workflows
// @Produce json
// @Security BearerAuth
// @Param id path string true "Workflow run ID (UUID)"
// @Success 200 {object} map[string]interface{} "Workflow run with steps"
// @Failure 404 {object} ErrorResponse "Workflow not found"
// @Failure 500 {object} ErrorResponse "Failed to get workflow"
// @Router /workflows/{id} [get]
func (h *WorkflowsHandler) GetWorkflow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	wf, err := h.store.GetWorkflow(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Workflow not found: "+id)
		return
	}

	steps, err := h.store.GetWorkflowSteps(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get workflow steps: "+err.Error())
		return
	}

	if steps == nil {
		steps = []flowengine.WorkflowStep{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow": wf,
		"steps":    steps,
	})
}
