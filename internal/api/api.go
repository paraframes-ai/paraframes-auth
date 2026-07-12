// Package api exposes the auth service over HTTP.
package api

import (
	"errors"
	"net/http"

	"github.com/paraframes-ai/paraframes-auth/internal/httpx"
	"github.com/paraframes-ai/paraframes-auth/internal/ratelimit"
	"github.com/paraframes-ai/paraframes-auth/internal/service"
	"github.com/paraframes-ai/paraframes-auth/internal/token"
)

// Handlers holds dependencies for the HTTP handlers.
type Handlers struct {
	svc     *service.Service
	issuer  *token.Issuer
	limiter *ratelimit.Limiter
}

// New constructs the Handlers.
func New(svc *service.Service, issuer *token.Issuer, limiter *ratelimit.Limiter) *Handlers {
	return &Handlers{svc: svc, issuer: issuer, limiter: limiter}
}

// writeServiceError maps a service-layer error to an HTTP response.
func writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var svcErr *service.Error
	if errors.As(err, &svcErr) {
		httpx.Error(w, r, httpx.NewError(statusForCode(svcErr.Code), svcErr.Code, svcErr.Message))
		return
	}
	httpx.Error(w, r, err)
}

func statusForCode(code string) int {
	switch code {
	case "validation_error", "weak_password", "invalid_body":
		return http.StatusBadRequest
	case "invalid_credentials", "invalid_token", "email_not_verified":
		return http.StatusUnauthorized
	case "beta_required", "account_disabled", "provider_not_enabled", "no_password":
		return http.StatusForbidden
	case "beta_code_invalid":
		return http.StatusForbidden
	case "not_found":
		return http.StatusNotFound
	case "email_taken", "passkey_exists":
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func requestMeta(r *http.Request) service.RequestMeta {
	return service.RequestMeta{
		UserAgent: r.UserAgent(),
		IP:        httpx.ClientIP(r),
	}
}
