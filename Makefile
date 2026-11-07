VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/imarey96/drifter/internal/cli.version=$(VERSION)

.PHONY: build test vet lint clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/drifter ./cmd/drifter

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin
