.PHONY: help build run test test-integration lint fmt vet tidy up down logs psql genkey

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build the server binary
	go build -o bin/server ./cmd/server

run: ## Run the server locally (expects a reachable Postgres)
	go run ./cmd/server

test: ## Run unit tests (no database required)
	go test ./... -short

test-integration: ## Run all tests including DB integration (needs TEST_DATABASE_URL)
	go test ./... -count=1

vet: ## Run go vet
	go vet ./...

fmt: ## Format code
	gofmt -w .

tidy: ## Tidy modules
	go mod tidy

up: ## Start Postgres + auth via docker compose
	docker compose up --build -d

down: ## Stop and remove containers
	docker compose down

logs: ## Tail the auth service logs
	docker compose logs -f auth

psql: ## Open a psql shell against the dev database
	docker compose exec db psql -U auth -d auth

genkey: ## Generate a P-256 EC private key for JWT signing
	@openssl ecparam -name prime256v1 -genkey -noout -out ec.pem && echo "wrote ec.pem"
