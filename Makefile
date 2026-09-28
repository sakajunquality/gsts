.PHONY: build test check image
build:
	go build -trimpath -o bin/gsts ./cmd/gsts

test:
	go test -race ./...

check:
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
	go test -race ./...

image:
	docker build -t gsts:dev .
