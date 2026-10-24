.PHONY: lint test build vuln licences release-check dev dev-agent proto api e2e release-snapshot

lint:
	golangci-lint run ./...

test:
	go test -race ./...

build:
	go build -trimpath -o bin/ ./cmd/nuxd ./cmd/nux

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

licences:
	go run github.com/google/go-licenses/v2@v2.0.1 check ./... --ignore github.com/nuxdeck/nuxdeck --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,0BSD,Zlib,Unlicense,AGPL-3.0

dev:
	@echo "make dev: not implemented yet (NUX-7)" >&2; exit 1

dev-agent:
	@echo "make dev-agent: not implemented yet (NUX-14)" >&2; exit 1

proto:
	@echo "make proto: not implemented yet (NUX-9)" >&2; exit 1

api:
	@echo "make api: not implemented yet (NUX-40)" >&2; exit 1

e2e:
	@echo "make e2e: not implemented yet (NUX-44)" >&2; exit 1

release-snapshot:
	go run github.com/goreleaser/goreleaser/v2@v2.19.0 release --snapshot --clean --skip=sign

release-check:
	go run github.com/goreleaser/goreleaser/v2@v2.19.0 check

