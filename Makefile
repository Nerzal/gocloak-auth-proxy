.PHONY: build test test-race bench lint vuln security check

build:
	go build ./...

test:
	go test ./...

test-race:
	go test -race -cover ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

lint:
	golangci-lint run

vuln:
	govulncheck ./...

security: vuln
	gosec ./...

check: lint security test-race bench build
