// Command server runs the Paraframes auth & identity HTTP service.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/paraframes-ai/paraframes-auth/internal/api"
	"github.com/paraframes-ai/paraframes-auth/internal/config"
	"github.com/paraframes-ai/paraframes-auth/internal/database"
	"github.com/paraframes-ai/paraframes-auth/internal/email"
	"github.com/paraframes-ai/paraframes-auth/internal/oauth"
	"github.com/paraframes-ai/paraframes-auth/internal/password"
	"github.com/paraframes-ai/paraframes-auth/internal/ratelimit"
	"github.com/paraframes-ai/paraframes-auth/internal/service"
	"github.com/paraframes-ai/paraframes-auth/internal/store"
	"github.com/paraframes-ai/paraframes-auth/internal/token"
	"github.com/paraframes-ai/paraframes-auth/internal/webauthnx"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	// Load .env in development if present (ignored if absent).
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	setupLogging(cfg)
	slog.Info("starting paraframes-auth", "env", cfg.Env, "addr", cfg.HTTPAddr)

	ctx := context.Background()

	// Database + migrations.
	pool, err := database.WaitForReady(ctx, cfg.DatabaseURL, 30*time.Second)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool); err != nil {
		return err
	}
	st := store.New(pool)

	// Token issuer.
	issuer, err := token.NewIssuer(cfg.JWTPrivateKeyPEM, cfg.JWTKeyID, cfg.Issuer, cfg.Audience, cfg.AccessTokenTTL)
	if err != nil {
		return err
	}
	if cfg.JWTPrivateKeyPEM == "" {
		if cfg.IsProduction() {
			return errors.New("refusing to start in production without JWT_PRIVATE_KEY_PEM")
		}
		slog.Warn("no JWT_PRIVATE_KEY_PEM set: generated an ephemeral signing key (tokens will not survive restart)")
	}

	// Social login verifiers.
	verifiers := oauth.NewVerifiers(oauth.Config{
		GoogleClientIDs: cfg.GoogleClientIDs,
		AppleClientIDs:  cfg.AppleClientIDs,
	})

	// WebAuthn (passkeys).
	waManager, err := webauthnx.New(cfg.RPID, cfg.RPDisplayName, cfg.RPOrigins)
	if err != nil {
		return err
	}

	// Mailer.
	var mailer email.Mailer = email.ConsoleMailer{}
	if cfg.SMTPHost != "" {
		mailer = email.SMTPMailer{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.EmailFrom,
		}
	}

	svc := service.New(st, issuer, verifiers, waManager, mailer, service.Config{
		PublicURL:       cfg.PublicURL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
		BetaAccessCode:  cfg.BetaAccessCode,
		PasswordParams: password.Params{
			Memory:      cfg.Argon2Memory,
			Iterations:  cfg.Argon2Iterations,
			Parallelism: cfg.Argon2Parallelism,
			SaltLength:  16,
			KeyLength:   32,
		},
	})

	limiter := ratelimit.New(cfg.RateLimitRPS, cfg.RateLimitBurst)
	handlers := api.New(svc, issuer, limiter)

	// Background cleanup of expired rows.
	go cleanupLoop(ctx, st)

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handlers.Router(st, cfg.CORSAllowedOrigins),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown.
	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case sig := <-stop:
		slog.Info("shutting down", "signal", sig.String())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func setupLogging(cfg *config.Config) {
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if cfg.IsDevelopment() {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func cleanupLoop(ctx context.Context, st *store.Store) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := st.DeleteExpired(ctx, time.Now()); err != nil {
				slog.Warn("cleanup failed", "err", err)
			}
		}
	}
}
