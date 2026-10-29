.PHONY: lint test build web vuln licences release-check dev dev-agent proto api api-check e2e release-snapshot bench load load-full

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

# api regenerates the Go client (pkg/client) and the TypeScript types (web/src/lib/api/schema.d.ts)
# from api/openapi.yaml. The generator versions are exact; output is deterministic, so api-check
# can prove that a committed client matches its description.
OAPI_CODEGEN := github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0
API_SPEC := api/openapi.yaml
API_GO_OUT := pkg/client/client.gen.go
API_TS_OUT := web/src/lib/api/schema.d.ts

api: web/node_modules
	go run $(OAPI_CODEGEN) --config api/oapi-codegen.yaml $(API_SPEC)
	@tmp=$$(mktemp) && { printf '// SPDX-License-Identifier: Apache-2.0\n\n'; cat $(API_GO_OUT); } > "$$tmp" && mv "$$tmp" $(API_GO_OUT) && chmod 644 $(API_GO_OUT)
	cd web && npx --no-install openapi-typescript ../$(API_SPEC) --output src/lib/api/schema.d.ts
	@tmp=$$(mktemp) && { printf '// SPDX-License-Identifier: AGPL-3.0-only\n\n'; cat $(API_TS_OUT); } > "$$tmp" && mv "$$tmp" $(API_TS_OUT) && chmod 644 $(API_TS_OUT)
	cd web && npx --no-install prettier --write src/lib/api/schema.d.ts >/dev/null

api-check:
	snapshot=$$(mktemp -d) && cp $(API_GO_OUT) $(API_TS_OUT) "$$snapshot"/ && \
	$(MAKE) --no-print-directory api && \
	{ cmp -s "$$snapshot/client.gen.go" $(API_GO_OUT) && cmp -s "$$snapshot/schema.d.ts" $(API_TS_OUT); }; \
	status=$$?; rm -rf "$$snapshot"; \
	if [ $$status -ne 0 ]; then echo "api-check: generated code is stale; run make api and commit the result" >&2; fi; \
	exit $$status

e2e:
	@echo "make e2e: not implemented yet (NUX-44)" >&2; exit 1

# bench runs the resource-budget tests (NFR-1 collector budget) and the server ingest benchmark.
# It runs without -race, because the budgets measure CPU and allocations.
bench:
	go test -count=1 -run '^TestNFR1' -bench . -benchmem ./internal/agent/metrics/ ./internal/server/metrics/

# load runs the smoke variant of the load harness (20 agents, 100 checks, 30 s), as CI does.
# load-full ramps to 200 agents and 1,000 checks for NFR-2 and NFR-4; it takes about 15 minutes at
# the default 5-minute windows. Pass LOAD_ARGS, for example LOAD_ARGS="-time-scale 10 -window 2m".
load: build
	go run ./test/load -nuxd bin/nuxd -profile smoke $(LOAD_ARGS)

load-full: build
	go run ./test/load -nuxd bin/nuxd -profile full $(LOAD_ARGS)

release-snapshot:
	go run github.com/goreleaser/goreleaser/v2@v2.19.0 release --snapshot --clean --skip=sign

release-check:
	go run github.com/goreleaser/goreleaser/v2@v2.19.0 check

