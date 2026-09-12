package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/api"
	"github.com/thrive-spectrexq/r3trive/internal/response"
)

var (
	serveAddr    string
	serveAPIKey  string
	serveTLSCert string
	serveTLSKey  string
	serveDryRun  bool
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the R3TRIVE REST API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := newStoreFromConfig(cfg)
			if err != nil {
				return err
			}
			defer store.Close()

			addr := serveAddr
			if addr == ":8080" && cfg != nil && cfg.API.Addr != "" {
				addr = cfg.API.Addr
			}
			apiKey := serveAPIKey
			if apiKey == "" && cfg != nil && cfg.API.APIKey != "" {
				apiKey = cfg.API.APIKey
			}
			tlsCert := serveTLSCert
			if tlsCert == "" && cfg != nil && cfg.API.TLSCert != "" {
				tlsCert = cfg.API.TLSCert
			}
			tlsKey := serveTLSKey
			if tlsKey == "" && cfg != nil && cfg.API.TLSKey != "" {
				tlsKey = cfg.API.TLSKey
			}

			respEngine := response.New(serveDryRun)

			rateLimit := 100
			var maxBodyBytes int64 = 1048576
			corsOrigins := []string{"*"}
			if cfg != nil {
				if cfg.API.RateLimit > 0 {
					rateLimit = cfg.API.RateLimit
				}
				if cfg.API.MaxBodyBytes > 0 {
					maxBodyBytes = cfg.API.MaxBodyBytes
				}
				if len(cfg.API.CORSOrigins) > 0 {
					corsOrigins = cfg.API.CORSOrigins
				}
			}

			serverConfig := api.ServerConfig{
				Addr:           addr,
				APIKey:         apiKey,
				TLSCert:        tlsCert,
				TLSKey:         tlsKey,
				ResponseEngine: respEngine,
				RateLimit:      rateLimit,
				MaxBodyBytes:   maxBodyBytes,
				CORSOrigins:    corsOrigins,
			}

			srv := api.NewServer(serverConfig, store)

			idleConnsClosed := make(chan struct{})
			go func() {
				sigint := make(chan os.Signal, 1)
				signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
				<-sigint

				slog.Info("Interrupt received, shutting down gracefully...")

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				if err := srv.Stop(ctx); err != nil {
					slog.Error("API server shutdown error", "error", err)
				}
				close(idleConnsClosed)
			}()

			if err := srv.Start(); err != nil && err.Error() != "http: Server closed" {
				slog.Error("API server error", "error", err)
				return err
			}

			<-idleConnsClosed
			slog.Info("Server exited properly")
			return nil
		},
	}

	cmd.Flags().StringVar(&serveAddr, "addr", ":8080", "Server address to listen on")
	cmd.Flags().StringVar(&serveAPIKey, "api-key", "", "API key for authentication")
	cmd.Flags().StringVar(&serveTLSCert, "tls-cert", "", "Path to TLS certificate file")
	cmd.Flags().StringVar(&serveTLSKey, "tls-key", "", "Path to TLS key file")
	cmd.Flags().BoolVar(&serveDryRun, "dry-run", true, "Run response actions in dry-run mode")

	return cmd
}
