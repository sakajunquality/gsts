.PHONY: build test check terraform-check image
build:
	go build -trimpath -o bin/gsts ./cmd/gsts

test:
	go test -race ./...

check:
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
	go test -race ./...
	terraform fmt -check -recursive terraform

terraform-check:
	terraform -chdir=terraform/google init -backend=false
	terraform -chdir=terraform/google validate
	terraform -chdir=terraform/google test

image:
	docker build -t gsts:dev .
