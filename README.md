# Paraframes Auth & Identity Platform

A self-hostable authentication and identity backend for the Paraframes **iOS**,
**macOS**, and **web** apps. Written in Go with the standard library router,
backed by PostgreSQL.

## Features

- **Email + password** — registration, login, email verification, password
  reset, and password change. Passwords are hashed with **Argon2id**.
- **Sign in with Apple** — verifies Apple identity tokens against Apple's JWKS.
- **Google OAuth** — verifies Google ID tokens against Google's JWKS.
- **Passkeys (WebAuthn/FIDO2)** — passwordless sign-in with Face ID / Touch ID
  and hardware keys. **Gated to beta testers** via a beta access code.
- **ES256 access tokens** — short-lived JWTs verifiable by any resource server
  through the published [JWKS](#verifying-access-tokens) endpoint.
- **Rotating refresh tokens** — opaque, hashed at rest, rotated on every use
  with **reuse detection**: replaying a rotated token revokes the entire
  session family.
- **Session management** — list and revoke individual sessions or all other
  devices.
- Production niceties: rate limiting, CORS, security headers, request IDs,
  structured logs, graceful shutdown, embedded SQL migrations, health/readiness
  probes, and a background cleanup job for expired rows.

## Architecture

```
cmd/server            entrypoint, wiring, graceful shutdown
internal/
  config              env-driven configuration
  httpx               JSON helpers, API errors, middleware (CORS, rate limit, etc.)
  token               ES256 JWT issue/verify + JWKS
  password            Argon2id hashing + password policy
  cryptorand          secure random tokens + hashing
  database            pgx pool + embedded migration runner
  store               typed Postgres repositories
  oauth               Google/Apple OIDC ID-token verification (cached JWKS)
  webauthnx           passkey (go-webauthn) adapter
  email               console (dev) + SMTP (prod) mailer
  ratelimit           per-IP token-bucket limiter
  service             transport-agnostic business logic
  api                 HTTP handlers + router
api/openapi.yaml      full API reference
```

The **service** layer holds all business logic and is independent of HTTP, so
it is unit-testable and could be exposed over gRPC or another transport later.

## Quick start (Docker Compose)

```bash
docker compose up --build
```

This starts PostgreSQL and the auth service on `http://localhost:8080`,
applying migrations automatically. In development, emails (verification /
reset links) are printed to the service logs instead of being sent.

```bash
# Register a user
curl -sX POST localhost:8080/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"supersecret123","display_name":"You"}'

# Log in
curl -sX POST localhost:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"supersecret123"}'
```

## Running locally without Docker

```bash
# Point DATABASE_URL at any reachable Postgres, then:
export DATABASE_URL="postgres://auth:auth@localhost:5432/auth?sslmode=disable"
make run
```

See `make help` for all targets (`build`, `test`, `test-integration`, `up`,
`down`, `logs`, `psql`, `genkey`).

## Configuration

All configuration is via environment variables — see [`.env.example`](.env.example)
for the full list with defaults. The essentials:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Postgres connection string (required) |
| `PUBLIC_URL` | Base URL used in email links and as the default JWT issuer |
| `JWT_PRIVATE_KEY_PEM` | PEM EC (P-256) signing key. Required in production; auto-generated in dev |
| `GOOGLE_CLIENT_IDS` | Comma-separated accepted Google audiences (client IDs) |
| `APPLE_CLIENT_IDS` | Comma-separated accepted Apple audiences (bundle/service IDs) |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGINS` | Passkey relying-party ID and allowed origins |
| `BETA_ACCESS_CODE` | Code users submit to `/v1/beta/enroll` to unlock passkeys |
| `SMTP_HOST` (+ port/user/pass) | Enables real email; unset ⇒ console mailer |

Generate a production signing key:

```bash
make genkey                        # writes ec.pem
export JWT_PRIVATE_KEY_PEM="$(cat ec.pem)"
```

## Token model

- **Access token** — ES256 JWT, 15-minute default lifetime, sent as
  `Authorization: Bearer <token>`. Claims: `sub` (user id), `email`,
  `email_verified`, `beta`, `sid` (session id), plus standard `iss`/`aud`/`exp`.
- **Refresh token** — opaque 256-bit token, stored only as a SHA-256 hash.
  Rotated on every `/v1/auth/token/refresh`. A replayed (already-rotated) token
  triggers a breach response that revokes every session for that user.

### Verifying access tokens

Resource servers verify access tokens **offline** using the public keys at:

```
GET /.well-known/jwks.json
```

No shared secret or round-trip to the auth service is needed — fetch and cache
the JWKS, then verify the JWT signature, `iss`, `aud`, and `exp`.

## Client integration

### Web (SPA)

1. `POST /v1/auth/login` (or a social/passkey flow) → store the access token in
   memory and the refresh token in a secure, `HttpOnly`-equivalent store.
2. Send `Authorization: Bearer <access_token>` on API calls.
3. On a `401`, call `/v1/auth/token/refresh` once and retry; if that also fails,
   send the user back to sign-in.
4. For **Google**, use Google Identity Services to obtain an ID token and POST
   it to `/v1/auth/oauth/google`.

### iOS / macOS

- **Sign in with Apple**: use `ASAuthorizationAppleIDProvider`. Send the
  returned `identityToken` to `/v1/auth/oauth/apple`. On the first authorization
  Apple also returns the user's name — pass it as `display_name` (it is not sent
  again on later sign-ins).
- **Passkeys**: use `ASAuthorizationPlatformPublicKeyCredentialProvider`. The
  `begin` endpoints return standard WebAuthn options (the `publicKey` object);
  hand them to the platform API, then POST the authenticator's response plus the
  returned `challenge_id` to the matching `finish` endpoint. Passkeys require a
  beta-tester account (see below).
- Store tokens in the Keychain.

### Passkeys are beta-gated

Passkey **registration** requires `is_beta_tester = true`. A user unlocks it by
submitting the configured beta code:

```bash
curl -sX POST localhost:8080/v1/beta/enroll \
  -H "Authorization: Bearer <access_token>" \
  -H 'Content-Type: application/json' \
  -d '{"code":"paraframes-beta"}'
```

Because the beta flag is embedded in the access token, the client should
refresh (or re-login) after enrolling so the new `beta` claim takes effect.

## API reference

The full API is documented in [`api/openapi.yaml`](api/openapi.yaml). Highlights:

| Method & path | Auth | Description |
| --- | --- | --- |
| `POST /v1/auth/register` | — | Email/password registration |
| `POST /v1/auth/login` | — | Email/password login |
| `POST /v1/auth/token/refresh` | — | Rotate refresh token |
| `POST /v1/auth/logout` | — | Revoke a session |
| `POST /v1/auth/email/verify` | — | Verify email |
| `POST /v1/auth/password/forgot` · `.../reset` | — | Password reset flow |
| `POST /v1/auth/oauth/google` · `.../apple` | — | Social login |
| `POST /v1/auth/passkeys/{register,login}/{begin,finish}` | mixed | Passkey ceremonies |
| `GET /v1/me` · `PATCH /v1/me` | ✔ | Profile |
| `POST /v1/auth/password/change` | ✔ | Change password |
| `GET /v1/sessions` · `DELETE /v1/sessions[/{id}]` | ✔ | Session management |
| `POST /v1/beta/enroll` | ✔ | Unlock passkeys |
| `GET /v1/passkeys` · `DELETE /v1/passkeys/{id}` | ✔ | Manage passkeys |

## Testing

```bash
make test              # unit tests (no database needed)

# Integration tests against a real Postgres:
export TEST_DATABASE_URL="postgres://auth:auth@localhost:5432/auth?sslmode=disable"
make test-integration
```

Unit tests cover Argon2id, ES256 token issue/verify, and OIDC verification
(against a mock JWKS). Integration tests cover registration, login, refresh
rotation + reuse detection, password reset session revocation, and passkey beta
gating.

## Security notes

- Passwords: Argon2id (64 MiB / 3 iterations / 2 lanes by default). Login does a
  dummy verify for unknown accounts to reduce timing side-channels.
- Refresh tokens and email tokens are stored only as SHA-256 hashes.
- Reuse of a rotated refresh token revokes the whole session family.
- Password reset and change revoke all existing sessions.
- Account-existence is never leaked by verification/reset endpoints (they always
  return `202`).
- Set a real `JWT_PRIVATE_KEY_PEM`, `BETA_ACCESS_CODE`, and restrictive
  `CORS_ALLOWED_ORIGINS` in production. Terminate TLS at your ingress and set
  `X-Forwarded-For` from a trusted proxy only.
