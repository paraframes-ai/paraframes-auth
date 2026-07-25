package api

import (
	"net/http"

	"github.com/paraframes-ai/paraframes-auth/internal/httpx"
	"github.com/paraframes-ai/paraframes-auth/internal/oauth"
)

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (h *Handlers) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	res, err := h.svc.Register(r.Context(), req.Email, req.Password, req.DisplayName, requestMeta(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, res)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	res, err := h.svc.Login(r.Context(), req.Email, req.Password, requestMeta(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	tokens, err := h.svc.Refresh(r.Context(), req.RefreshToken, requestMeta(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

func (h *Handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := h.svc.Logout(r.Context(), req.RefreshToken); err != nil {
		httpx.Error(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

func (h *Handlers) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := h.svc.VerifyEmail(r.Context(), req.Token); err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

type emailOnlyRequest struct {
	Email string `json:"email"`
}

func (h *Handlers) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	var req emailOnlyRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := h.svc.ResendVerification(r.Context(), req.Email); err != nil {
		httpx.Error(w, r, err)
		return
	}
	// Always return 202 to avoid leaking whether the email exists.
	httpx.JSON(w, http.StatusAccepted, map[string]string{"status": "sent_if_exists"})
}

func (h *Handlers) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req emailOnlyRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := h.svc.ForgotPassword(r.Context(), req.Email); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]string{"status": "sent_if_exists"})
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (h *Handlers) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := h.svc.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
}

type socialLoginRequest struct {
	IDToken     string `json:"id_token"`
	DisplayName string `json:"display_name"`
}

func (h *Handlers) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	h.handleSocialLogin(w, r, oauth.ProviderGoogle)
}

func (h *Handlers) handleAppleLogin(w http.ResponseWriter, r *http.Request) {
	h.handleSocialLogin(w, r, oauth.ProviderApple)
}

func (h *Handlers) handleSocialLogin(w http.ResponseWriter, r *http.Request, provider oauth.Provider) {
	var req socialLoginRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if req.IDToken == "" {
		httpx.Error(w, r, httpx.BadRequest("validation_error", "id_token is required"))
		return
	}
	res, err := h.svc.SocialLogin(r.Context(), provider, req.IDToken, req.DisplayName, requestMeta(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}
