package api

import (
	"context"
	"net/http"
	"time"

	"github.com/paraframes-ai/paraframes-auth/internal/httpx"
	"github.com/paraframes-ai/paraframes-auth/internal/store"
)

// Router builds the full HTTP handler with middleware applied.
func (h *Handlers) Router(st *store.Store, corsOrigins []string) http.Handler {
	mux := http.NewServeMux()

	// System.
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	mux.HandleFunc("GET /readyz", h.readyz(st))
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)

	// Auth (public, rate-limited).
	mux.HandleFunc("POST /v1/auth/register", h.rateLimit(h.handleRegister))
	mux.HandleFunc("POST /v1/auth/login", h.rateLimit(h.handleLogin))
	mux.HandleFunc("POST /v1/auth/token/refresh", h.rateLimit(h.handleRefresh))
	mux.HandleFunc("POST /v1/auth/logout", h.handleLogout)
	mux.HandleFunc("POST /v1/auth/email/verify", h.rateLimit(h.handleVerifyEmail))
	mux.HandleFunc("POST /v1/auth/email/resend", h.rateLimit(h.handleResendVerification))
	mux.HandleFunc("POST /v1/auth/password/forgot", h.rateLimit(h.handleForgotPassword))
	mux.HandleFunc("POST /v1/auth/password/reset", h.rateLimit(h.handleResetPassword))

	// Social login.
	mux.HandleFunc("POST /v1/auth/oauth/google", h.rateLimit(h.handleGoogleLogin))
	mux.HandleFunc("POST /v1/auth/oauth/apple", h.rateLimit(h.handleAppleLogin))

	// Passkeys (beta-gated in the service layer).
	mux.HandleFunc("POST /v1/auth/passkeys/login/begin", h.rateLimit(h.handlePasskeyLoginBegin))
	mux.HandleFunc("POST /v1/auth/passkeys/login/finish", h.rateLimit(h.handlePasskeyLoginFinish))
	mux.HandleFunc("POST /v1/auth/passkeys/register/begin", h.requireAuth(h.handlePasskeyRegisterBegin))
	mux.HandleFunc("POST /v1/auth/passkeys/register/finish", h.requireAuth(h.handlePasskeyRegisterFinish))

	// Account (authenticated).
	mux.HandleFunc("GET /v1/me", h.requireAuth(h.handleMe))
	mux.HandleFunc("PATCH /v1/me", h.requireAuth(h.handleUpdateProfile))
	mux.HandleFunc("POST /v1/auth/password/change", h.requireAuth(h.handleChangePassword))
	mux.HandleFunc("GET /v1/sessions", h.requireAuth(h.handleListSessions))
	mux.HandleFunc("DELETE /v1/sessions", h.requireAuth(h.handleRevokeOtherSessions))
	mux.HandleFunc("DELETE /v1/sessions/{id}", h.requireAuth(h.handleRevokeSession))
	mux.HandleFunc("POST /v1/beta/enroll", h.requireAuth(h.handleBetaEnroll))
	mux.HandleFunc("GET /v1/passkeys", h.requireAuth(h.handleListPasskeys))
	mux.HandleFunc("DELETE /v1/passkeys/{id}", h.requireAuth(h.handleDeletePasskey))

	return httpx.Chain(mux,
		httpx.Recover,
		httpx.RequestIDMiddleware,
		httpx.Logging,
		httpx.SecurityHeaders,
		httpx.CORS(corsOrigins),
	)
}

func (h *Handlers) handleHealthz(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handlers) readyz(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := st.Pool().Ping(ctx); err != nil {
			httpx.Error(w, r, httpx.NewError(http.StatusServiceUnavailable, "not_ready", "database unavailable"))
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

func (h *Handlers) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	httpx.JSON(w, http.StatusOK, h.issuer.JWKS())
}
