package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/paraframes-ai/paraframes-auth/internal/httpx"
)

// Passkey ceremonies exchange raw WebAuthn JSON. Begin endpoints return the
// creation/assertion options plus a challenge_id the client echoes back to the
// matching finish endpoint alongside the authenticator's response.

func (h *Handlers) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	options, challengeID, err := h.svc.BeginPasskeyRegistration(r.Context(), userID)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"challenge_id": challengeID,
		"publicKey":    options,
	})
}

func (h *Handlers) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	req, err := decodePasskeyFinish(w, r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	view, err := h.svc.FinishPasskeyRegistration(r.Context(), userID, req.ChallengeID, req.Credential, req.Name)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, view)
}

type passkeyLoginBeginRequest struct {
	Email string `json:"email"`
}

func (h *Handlers) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req passkeyLoginBeginRequest
	// Body is optional (discoverable login sends none).
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req)
	options, challengeID, err := h.svc.BeginPasskeyLogin(r.Context(), req.Email)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"challenge_id": challengeID,
		"publicKey":    options,
	})
}

func (h *Handlers) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	req, err := decodePasskeyFinish(w, r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	res, err := h.svc.FinishPasskeyLogin(r.Context(), req.ChallengeID, req.Credential, requestMeta(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

func (h *Handlers) handleListPasskeys(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	passkeys, err := h.svc.ListPasskeys(r.Context(), userID)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"passkeys": passkeys})
}

func (h *Handlers) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	userID, _ := httpx.UserID(r.Context())
	id := r.PathValue("id")
	if err := h.svc.DeletePasskey(r.Context(), userID, id); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// passkeyFinish is the shared shape of both finish requests.
type passkeyFinish struct {
	ChallengeID string          `json:"challenge_id"`
	Name        string          `json:"name"`
	Credential  json.RawMessage `json:"credential"`
}

func decodePasskeyFinish(w http.ResponseWriter, r *http.Request) (*passkeyFinish, error) {
	var req passkeyFinish
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		return nil, err
	}
	if req.ChallengeID == "" || len(req.Credential) == 0 {
		return nil, httpx.BadRequest("validation_error", "challenge_id and credential are required")
	}
	return &req, nil
}
