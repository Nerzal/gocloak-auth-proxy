.PHONY: build test test-race bench bench-profile bench-isolated bench-compare bench-keycloak bench-charts lint vuln security check

build:
	go build ./...

test:
	go test ./...

test-race:
	go test -race -cover ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

bench-profile:
	bash ./bench/run_profile.sh

bench-isolated:
	ONLY_GOCLOAK=1 bash ./bench/run_compare.sh

bench-compare:
	bash ./bench/run_compare.sh

bench-keycloak:
	bash ./bench/run_keycloak.sh

bench-charts:
	python3 ./bench/render_charts.py

lint:
	golangci-lint run

vuln:
	govulncheck ./...

security: vuln
	gosec ./...

check: lint security test-race bench build
