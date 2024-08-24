.PHONY: run-docker-local
run-docker-local:
	docker compose --env-file .env --env-file .env.local -f docker-compose.yml -f docker-compose.local.yml up --build --remove-orphans

.PHONY: stop-docker-local
stop-docker:
	docker compose --env-file .env --env-file .env.local -f docker-compose.yml -f docker-compose.local.yml down

.PHONY: reset-docker-local
reset-docker-local:
	docker compose --env-file .env --env-file .env.local -f docker-compose.yml -f docker-compose.local.yml down -v
	docker compose --env-file .env --env-file .env.local -f docker-compose.yml -f docker-compose.local.yml up -d

.PHONY: run-docker-prod
run-docker-prod:
	docker compose --env-file .env --env-file .env.prod -f docker-compose.yml -f docker-compose.prod.yml up -d --build --remove-orphans

.PHONY: stop-docker-prod
stop-docker-prod:
	docker compose --env-file .env --env-file .env.prod -f docker-compose.yml -f docker-compose.prod.yml down

.PHONY: reset-docker-prod
reset-docker-prod:
	docker compose --env-file .env --env-file .env.prod -f docker-compose.yml -f docker-compose.prod.yml down -v
	docker compose --env-file .env --env-file .env.prod -f docker-compose.yml -f docker-compose.prod.yml up -d

.PHONY: pull-images
pull-images:
	docker compose --env-file .env --env-file .env.prod -f docker-compose.yml -f docker-compose.prod.yml pull

.PHONY: build

.DEFAULT_GOAL := build

.PHONY: lint
lint:
	golangci-lint run --config .golangci-lint.yaml

.PHONY: build
build:
	go build -o ./.bin/server cmd/app/main.go

.PHONY: build-docker
build-docker:
	docker build -t auth .

.PHONY: run
run: build
	./.bin/server

.PHONY: test
test:
	go test -v ./...

.PHONY: test-cover
test-cover:
	go test -coverprofile=coverage.out -covermode=atomic ./...

.PHONY: clean
clean:
	rm -rf ./.bin