package api

import (
	"net/http"

	"github.com/paraframes-ai/paraframes-auth/internal/httpx"
)

func (h *Handlers) handleMe(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	view, err := h.svc.Me(r.Context(), userID)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, view)
}

type updateProfileRequest struct {
	DisplayName string `json:"display_name"`
}

func (h *Handlers) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	var req updateProfileRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	view, err := h.svc.UpdateProfile(r.Context(), userID, req.DisplayName)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, view)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *Handlers) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	sessionID, _ := httpx.SessionID(r.Context())
	var req changePasswordRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := h.svc.ChangePassword(r.Context(), userID, req.CurrentPassword, req.NewPassword, sessionID); err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

func (h *Handlers) handleListSessions(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	sessionID, _ := httpx.SessionID(r.Context())
	sessions, err := h.svc.ListSessions(r.Context(), userID, sessionID)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (h *Handlers) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	id := r.PathValue("id")
	if err := h.svc.RevokeSession(r.Context(), userID, id); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	sessionID, _ := httpx.SessionID(r.Context())
	if err := h.svc.RevokeOtherSessions(r.Context(), userID, sessionID); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type betaEnrollRequest struct {
	Code string `json:"code"`
}

func (h *Handlers) handleBetaEnroll(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	var req betaEnrollRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, r, err)
		return
	}
	view, err := h.svc.EnrollBeta(r.Context(), userID, req.Code)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, view)
}
