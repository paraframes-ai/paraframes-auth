// Package httpx contains HTTP helpers: JSON encoding, structured API errors, and
// request context accessors shared across handlers and middleware.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
)

// APIError is a structured, client-facing error.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
	// Details optionally carries field-level validation info.
	Details map[string]string `json:"details,omitempty"`
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

// NewError constructs an APIError.
func NewError(status int, code, message string) *APIError {
	return &APIError{Status: status, Code: code, Message: message}
}

// Common error constructors.
func BadRequest(code, msg string) *APIError   { return NewError(http.StatusBadRequest, code, msg) }
func Unauthorized(code, msg string) *APIError { return NewError(http.StatusUnauthorized, code, msg) }
func Forbidden(code, msg string) *APIError    { return NewError(http.StatusForbidden, code, msg) }
func NotFound(code, msg string) *APIError     { return NewError(http.StatusNotFound, code, msg) }
func Conflict(code, msg string) *APIError     { return NewError(http.StatusConflict, code, msg) }
func TooManyRequests(code, msg string) *APIError {
	return NewError(http.StatusTooManyRequests, code, msg)
}
func Internal(msg string) *APIError {
	return NewError(http.StatusInternalServerError, "internal_error", msg)
}

// JSON writes v as a JSON response with the given status code.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// Error writes err as a JSON error response. Non-APIErrors are logged and
// rendered as a generic 500 to avoid leaking internals.
func Error(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.Status >= 500 {
			slog.ErrorContext(r.Context(), "request failed", "code", apiErr.Code, "err", apiErr.Message, "request_id", RequestID(r.Context()))
		}
		JSON(w, apiErr.Status, map[string]any{"error": apiErr})
		return
	}
	slog.ErrorContext(r.Context(), "unhandled error", "err", err.Error(), "request_id", RequestID(r.Context()))
	JSON(w, http.StatusInternalServerError, map[string]any{
		"error": &APIError{Code: "internal_error", Message: "an unexpected error occurred"},
	})
}

// DecodeJSON decodes the request body into v, enforcing a size limit and
// rejecting unknown fields. It returns a BadRequest APIError on failure.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	const maxBody = 1 << 20 // 1 MiB
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return BadRequest("invalid_body", "request body is empty")
		}
		return BadRequest("invalid_body", "request body is not valid JSON: "+err.Error())
	}
	return nil
}

// --- request-scoped context values ---

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyUserID
	ctxKeySessionID
)

// WithRequestID stores a request ID on the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

// RequestID retrieves the request ID from the context.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// WithAuth stores the authenticated user ID and session ID on the context.
func WithAuth(ctx context.Context, userID, sessionID string) context.Context {
	ctx = context.WithValue(ctx, ctxKeyUserID, userID)
	return context.WithValue(ctx, ctxKeySessionID, sessionID)
}

// UserID returns the authenticated user ID, if any.
func UserID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeyUserID).(string)
	return v, ok && v != ""
}

// SessionID returns the authenticated session ID, if any.
func SessionID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeySessionID).(string)
	return v, ok && v != ""
}
