.PHONY: build test lint docs-check install

build:
	go build -o bin/keyfarer ./cmd/keyfarer

install:
	go install ./cmd/keyfarer

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run ./... || true

docs-check:
	./scripts/docs-check.sh
