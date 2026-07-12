// Package config loads and validates runtime configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration for the auth service.
type Config struct {
	Env         string // "development" | "staging" | "production"
	HTTPAddr    string // e.g. ":8080"
	PublicURL   string // externally reachable base URL, used in emails and OIDC issuer
	Issuer      string // JWT issuer (iss claim)
	Audience    string // JWT audience (aud claim)
	DatabaseURL string

	// Token lifetimes.
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// Signing key. PEM-encoded EC private key (ES256). If empty in development a
	// throwaway key is generated at boot.
	JWTPrivateKeyPEM string
	JWTKeyID         string

	// Social login.
	GoogleClientIDs []string // accepted aud values for Google ID tokens
	AppleClientIDs  []string // accepted aud values for Apple ID tokens (bundle/service IDs)

	// WebAuthn / passkeys.
	RPID          string   // relying party ID, e.g. "auth.example.com"
	RPDisplayName string   // human-readable app name
	RPOrigins     []string // allowed origins, e.g. https://app.example.com, ios app origins

	// Beta gating for passkeys.
	BetaAccessCode string

	// Email.
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	EmailFrom    string

	// CORS.
	CORSAllowedOrigins []string

	// Security.
	Argon2Memory      uint32
	Argon2Iterations  uint32
	Argon2Parallelism uint8

	// Rate limiting (requests per second and burst, per client IP, on auth endpoints).
	RateLimitRPS   float64
	RateLimitBurst int
}

// Load reads configuration from the environment, applying sane defaults.
func Load() (*Config, error) {
	c := &Config{
		Env:                getEnv("APP_ENV", "development"),
		HTTPAddr:           getEnv("HTTP_ADDR", ":8080"),
		PublicURL:          getEnv("PUBLIC_URL", "http://localhost:8080"),
		DatabaseURL:        getEnv("DATABASE_URL", "postgres://auth:auth@localhost:5432/auth?sslmode=disable"),
		AccessTokenTTL:     getDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:    getDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		JWTPrivateKeyPEM:   os.Getenv("JWT_PRIVATE_KEY_PEM"),
		JWTKeyID:           getEnv("JWT_KEY_ID", "auth-key-1"),
		GoogleClientIDs:    getList("GOOGLE_CLIENT_IDS"),
		AppleClientIDs:     getList("APPLE_CLIENT_IDS"),
		RPID:               getEnv("WEBAUTHN_RP_ID", "localhost"),
		RPDisplayName:      getEnv("WEBAUTHN_RP_NAME", "Paraframes"),
		RPOrigins:          getList("WEBAUTHN_RP_ORIGINS"),
		BetaAccessCode:     os.Getenv("BETA_ACCESS_CODE"),
		SMTPHost:           os.Getenv("SMTP_HOST"),
		SMTPPort:           getInt("SMTP_PORT", 587),
		SMTPUsername:       os.Getenv("SMTP_USERNAME"),
		SMTPPassword:       os.Getenv("SMTP_PASSWORD"),
		EmailFrom:          getEnv("EMAIL_FROM", "no-reply@paraframes.local"),
		CORSAllowedOrigins: getList("CORS_ALLOWED_ORIGINS"),
		Argon2Memory:       uint32(getInt("ARGON2_MEMORY_KIB", 64*1024)),
		Argon2Iterations:   uint32(getInt("ARGON2_ITERATIONS", 3)),
		Argon2Parallelism:  uint8(getInt("ARGON2_PARALLELISM", 2)),
		RateLimitRPS:       getFloat("RATE_LIMIT_RPS", 5),
		RateLimitBurst:     getInt("RATE_LIMIT_BURST", 10),
	}

	c.Issuer = getEnv("JWT_ISSUER", c.PublicURL)
	c.Audience = getEnv("JWT_AUDIENCE", "paraframes-app")

	if len(c.RPOrigins) == 0 {
		c.RPOrigins = []string{c.PublicURL}
	}
	if len(c.CORSAllowedOrigins) == 0 {
		c.CORSAllowedOrigins = []string{"*"}
	}

	return c, c.validate()
}

func (c *Config) validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if c.IsProduction() {
		if c.JWTPrivateKeyPEM == "" {
			return fmt.Errorf("JWT_PRIVATE_KEY_PEM is required in production")
		}
		if len(c.GoogleClientIDs) == 0 && len(c.AppleClientIDs) == 0 {
			// not fatal, but warn-worthy; allow email-only deployments
		}
	}
	return nil
}

// IsProduction reports whether the service is running in production mode.
func (c *Config) IsProduction() bool { return c.Env == "production" }

// IsDevelopment reports whether the service is running in development mode.
func (c *Config) IsDevelopment() bool { return c.Env == "development" }

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func getList(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
