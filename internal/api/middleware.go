package api

import (
	"net/http"
	"strings"

	"github.com/paraframes-ai/paraframes-auth/internal/httpx"
)

// requireAuth authenticates the request via a Bearer access token, storing the
// user and session IDs on the request context.
func (h *Handlers) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authz, prefix) {
			httpx.Error(w, r, httpx.Unauthorized("missing_token", "missing bearer token"))
			return
		}
		raw := strings.TrimSpace(authz[len(prefix):])
		claims, err := h.issuer.Verify(raw)
		if err != nil {
			httpx.Error(w, r, httpx.Unauthorized("invalid_token", "access token is invalid or expired"))
			return
		}
		ctx := httpx.WithAuth(r.Context(), claims.Subject, claims.SessionID)
		next(w, r.WithContext(ctx))
	}
}

// rateLimit applies per-IP rate limiting to sensitive endpoints.
func (h *Handlers) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.limiter != nil && !h.limiter.Allow(httpx.ClientIP(r)) {
			httpx.Error(w, r, httpx.TooManyRequests("rate_limited", "too many requests; please slow down"))
			return
		}
		next(w, r)
	}
}
