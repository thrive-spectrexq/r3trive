package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/thrive-spectrexq/r3trive/internal/api/handlers"
	apimiddleware "github.com/thrive-spectrexq/r3trive/internal/api/middleware"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
)

// ServerConfig holds the configuration for the API server.
type ServerConfig struct {
	Addr           string
	APIKey         string
	TLSCert        string
	TLSKey         string
	ResponseEngine handlers.ActionExecutor
	RateLimit      int
	MaxBodyBytes   int64
	CORSOrigins    []string
}

// Server represents the REST API server.
type Server struct {
	httpServer *http.Server
	store      storage.Store
	config     ServerConfig
}

// requestIDMiddleware injects a UUID based request ID if one isn't present.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		ctx = context.WithValue(ctx, middleware.RequestIDKey, reqID)
		w.Header().Set("X-Request-Id", reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// NewServer initializes a new API server with the given config and store.
func NewServer(cfg ServerConfig, store storage.Store) *Server {
	r := chi.NewRouter()

	// Standard middleware
	r.Use(requestIDMiddleware)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Rate limiting middleware
	rateLimit := cfg.RateLimit
	if rateLimit <= 0 {
		rateLimit = 100
	}
	r.Use(apimiddleware.RateLimit(rateLimit))

	// Request size limit middleware
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 1048576 // 1MB default
	}
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
			next.ServeHTTP(w, r)
		})
	})

	// Configurable CORS middleware
	allowedOrigins := cfg.CORSOrigins
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"*"}
	}
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			isAllowed := false
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					isAllowed = true
					break
				}
			}
			if isAllowed {
				if origin != "" && allowedOrigins[0] != "*" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				} else {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token, X-API-Key, X-Request-Id")
			if r.Method == "OPTIONS" {
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	r.Get("/swagger", HandleSwaggerUI)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", handlers.GetHealth(store))
		r.Get("/openapi.json", HandleOpenAPIJSON)

		r.Group(func(r chi.Router) {
			// API Key authentication middleware
			r.Use(apimiddleware.APIKeyAuth(cfg.APIKey))

			r.Route("/events", func(r chi.Router) {
				r.Get("/", handlers.QueryEvents(store))
				r.Get("/{id}", handlers.GetEvent(store))
			})

			r.Route("/alerts", func(r chi.Router) {
				r.Get("/", handlers.ListAlerts(store))
				r.Put("/{id}/acknowledge", handlers.AcknowledgeAlert(store))
			})

			r.Route("/incidents", func(r chi.Router) {
				r.Get("/", handlers.ListIncidents(store))
				r.Get("/{id}", handlers.GetIncident(store))
				r.Put("/{id}/status", handlers.UpdateIncidentStatus(store))
			})

			r.Route("/hosts", func(r chi.Router) {
				r.Get("/", handlers.ListHosts(store))
				r.Get("/{id}", handlers.GetHost(store))
				r.Post("/", handlers.RegisterHost(store))
			})

			r.Route("/rules", func(r chi.Router) {
				r.Get("/", handlers.ListRules(store))
				r.Post("/", handlers.CreateRule(store))
				r.Put("/{id}", handlers.UpdateRule(store))
				r.Delete("/{id}", handlers.DeleteRule(store))
			})

			r.Route("/iocs", func(r chi.Router) {
				r.Get("/", handlers.QueryIOCs(store))
				r.Post("/", handlers.AddIOC(store))
			})

			r.Route("/response", func(r chi.Router) {
				r.Post("/execute", handlers.ExecuteAction(store, cfg.ResponseEngine))
			})
		})
	})

	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.Addr,
			Handler:           r,
			ReadHeaderTimeout: 5 * time.Second,
		},
		store:  store,
		config: cfg,
	}
}

// Start runs the HTTP server.
func (s *Server) Start() error {
	slog.Info("Starting API server", "addr", s.config.Addr)
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		return s.httpServer.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	return s.httpServer.ListenAndServe()
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	slog.Info("Shutting down API server gracefully")
	return s.httpServer.Shutdown(ctx)
}
