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
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
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
			dbPath := "r3trive.db"
			if cfg != nil && cfg.Storage.DSN != "" {
				dbPath = cfg.Storage.DSN
			}

			store, err := sqlite.New(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()

			respEngine := response.New(serveDryRun)

			serverConfig := api.ServerConfig{
				Addr:           serveAddr,
				APIKey:         serveAPIKey,
				TLSCert:        serveTLSCert,
				TLSKey:         serveTLSKey,
				ResponseEngine: respEngine,
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
