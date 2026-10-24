.PHONY: lint test build web vuln licences release-check dev dev-agent proto api e2e release-snapshot

web/node_modules: web/package-lock.json
	cd web && npm ci
	@touch web/node_modules

lint: web/node_modules
	golangci-lint run ./...
	go run github.com/bufbuild/buf/cmd/buf@v1.75.0 lint
	cd web && npm run lint && npm run check

test: web/node_modules
	go test -race ./...
	cd web && npm test
	bash deploy/install/install_test.sh
	bash deploy/release/next-version_test.sh

web: web/node_modules
	cd web && npm run build

build: web
	go build -trimpath -o bin/ ./cmd/nuxd ./cmd/nux

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

licences:
	go run github.com/google/go-licenses/v2@v2.0.1 check ./... --ignore github.com/nuxdeck/nuxdeck --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,0BSD,Zlib,Unlicense,AGPL-3.0

dev: web/node_modules
	@echo "UI with hot reload: http://localhost:5173 (API proxied to https://localhost:8443)"
	@mkdir -p .dev-data
	@trap 'kill 0' INT TERM EXIT; \
	  NUXD_DATA_DIR="$(CURDIR)/.dev-data" NUXD_HTTPS_ADDR=127.0.0.1:8443 NUXD_REDIRECT_ADDR=127.0.0.1:8080 go run ./cmd/nuxd & \
	  (cd web && npm run dev) & \
	  wait

dev-agent:
	@echo "make dev-agent: not implemented yet (NUX-14)" >&2; exit 1

proto:
	go run github.com/bufbuild/buf/cmd/buf@v1.75.0 generate

api:
	@echo "make api: not implemented yet (NUX-40)" >&2; exit 1

e2e:
	@echo "make e2e: not implemented yet (NUX-44)" >&2; exit 1

release-snapshot:
	go run github.com/goreleaser/goreleaser/v2@v2.19.0 release --snapshot --clean --skip=sign

release-check:
	go run github.com/goreleaser/goreleaser/v2@v2.19.0 check

