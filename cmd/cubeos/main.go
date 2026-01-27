// Package main is the entry point for the CubeOS API server.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/docker/docker/client"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/nuclearlighters/cubeos/internal/api"
	"github.com/nuclearlighters/cubeos/internal/config"
	"github.com/nuclearlighters/cubeos/internal/docker"
)

func main() {
	// Load configuration
	cfg := config.Get()

	// Setup logging
	setupLogging(cfg.LogLevel)

	log.Info().
		Str("version", cfg.Version).
		Str("listen", cfg.ListenAddr()).
		Msg("Starting CubeOS API server")

	// Initialize Docker client
	dockerClient, err := initDockerClient(cfg)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to connect to Docker - running in degraded mode")
	}

	// Create Docker manager
	var dockerManager *docker.Manager
	if dockerClient != nil {
		dockerManager = docker.NewManager(dockerClient)
	}

	// Create router
	r := chi.NewRouter()

	// Middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(corsMiddleware)

	// Register routes
	registerRoutes(r, cfg, dockerClient, dockerManager)

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.ListenAddr(),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info().Str("addr", cfg.ListenAddr()).Msg("HTTP server listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down server...")

	// Give outstanding requests 10 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server forced to shutdown")
	}

	// Cleanup
	if dockerClient != nil {
		if err := dockerClient.Close(); err != nil {
			log.Warn().Err(err).Msg("Error closing Docker client")
		}
	}

	log.Info().Msg("Server stopped")
}

// setupLogging configures zerolog based on log level.
func setupLogging(level string) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	switch level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

// initDockerClient creates a Docker client connected to the configured socket.
func initDockerClient(cfg *config.Settings) (*client.Client, error) {
	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}

	if os.Getenv("DOCKER_HOST") == "" {
		opts = append(opts, client.WithHost("unix://"+cfg.DockerSocket))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = cli.Ping(ctx)
	if err != nil {
		cli.Close()
		return nil, err
	}

	log.Info().Str("socket", cfg.DockerSocket).Msg("Connected to Docker")
	return cli, nil
}

// registerRoutes sets up all API routes.
func registerRoutes(r chi.Router, cfg *config.Settings, dockerClient *client.Client, dockerManager *docker.Manager) {
	// Initialize handlers
	healthHandler := api.NewHealthHandler(cfg, dockerClient)
	systemHandler := api.NewSystemHandler()
	servicesHandler := api.NewServicesHandler(dockerManager)

	// Health check endpoints (no auth required)
	r.Get("/health", healthHandler.ServeHTTP)
	r.Get("/api/health", healthHandler.ServeHTTP)

	// Root endpoint - API info
	r.Get("/", rootHandler(cfg))
	r.Get("/api", apiInfoHandler(cfg))

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		// System endpoints
		r.Route("/system", func(r chi.Router) {
			r.Get("/info", systemHandler.GetInfo)
			r.Get("/stats", systemHandler.GetStats)
			r.Get("/hostname", systemHandler.GetHostname)
			r.Get("/version", systemHandler.GetVersion)
			r.Post("/reboot", systemHandler.Reboot)
			r.Post("/shutdown", systemHandler.Shutdown)
		})

		// Service/Container endpoints
		r.Route("/services", func(r chi.Router) {
			r.Get("/", servicesHandler.List)
			r.Get("/status", servicesHandler.Status)
			r.Get("/{name}", servicesHandler.Get)
			r.Post("/{name}/start", servicesHandler.Start)
			r.Post("/{name}/stop", servicesHandler.Stop)
			r.Post("/{name}/restart", servicesHandler.Restart)
			r.Get("/{name}/logs", servicesHandler.Logs)
			r.Get("/{name}/stats", servicesHandler.Stats)
		})

		// Auth endpoints (Sprint 1.1 - later)
		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", notImplementedHandler)
			r.Post("/logout", notImplementedHandler)
			r.Get("/me", notImplementedHandler)
		})
	})
}

// rootHandler returns a handler for the root endpoint.
func rootHandler(cfg *config.Settings) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api", http.StatusTemporaryRedirect)
	}
}

// apiInfoHandler returns API metadata.
func apiInfoHandler(cfg *config.Settings) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{
	"name": "CubeOS API",
	"version": "` + cfg.Version + `",
	"endpoints": {
		"health": "GET /health, GET /api/health",
		"system_info": "GET /api/v1/system/info",
		"system_stats": "GET /api/v1/system/stats",
		"system_reboot": "POST /api/v1/system/reboot",
		"system_shutdown": "POST /api/v1/system/shutdown",
		"services_list": "GET /api/v1/services",
		"services_status": "GET /api/v1/services/status",
		"services_get": "GET /api/v1/services/{name}",
		"services_start": "POST /api/v1/services/{name}/start",
		"services_stop": "POST /api/v1/services/{name}/stop",
		"services_restart": "POST /api/v1/services/{name}/restart",
		"services_logs": "GET /api/v1/services/{name}/logs",
		"services_stats": "GET /api/v1/services/{name}/stats",
		"auth": "/api/v1/auth/* (not implemented)"
	}
}`
		w.Write([]byte(response))
	}
}

// notImplementedHandler returns 501 Not Implemented.
func notImplementedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error": "not implemented", "message": "This endpoint is planned but not yet available"}`))
}

// requestLogger is middleware that logs HTTP requests using zerolog.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		log.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", ww.Status()).
			Dur("duration", time.Since(start)).
			Str("remote", r.RemoteAddr).
			Msg("request")
	})
}

// corsMiddleware adds CORS headers for cross-origin requests.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
