.PHONY: lint test build vuln licences dev dev-agent proto api e2e release-snapshot

lint:
	golangci-lint run ./...

test:
	go test -race ./...

build:
	go build ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

licences:
	go run github.com/google/go-licenses/v2@v2.0.1 check ./... --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,0BSD,Zlib,Unlicense,AGPL-3.0

dev:
	@echo "make dev: not implemented yet (NUX-5, NUX-7)" >&2; exit 1

dev-agent:
	@echo "make dev-agent: not implemented yet (NUX-14)" >&2; exit 1

proto:
	@echo "make proto: not implemented yet (NUX-9)" >&2; exit 1

api:
	@echo "make api: not implemented yet (NUX-40)" >&2; exit 1

e2e:
	@echo "make e2e: not implemented yet (NUX-44)" >&2; exit 1

release-snapshot:
	@echo "make release-snapshot: not implemented yet (NUX-4)" >&2; exit 1

