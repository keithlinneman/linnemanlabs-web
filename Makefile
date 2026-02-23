.PHONY: build run test fuzz cover clean release lint bench vet check tidy

build:
	go build -o bin/linnemanlabs-web ./cmd/server

run: build
	LMLABS_ENABLE_CONTENT_UPDATES=false \
	LMLABS_ENABLE_TRACING=false \
	LMLABS_ENABLE_PYROSCOPE=false \
	LMLABS_HTTP_PORT=8080 \
	./bin/linnemanlabs-web

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fuzz:
	@echo "Fuzzing FuzzExtractTarGzToMem..."
	go test -fuzz=FuzzExtractTarGzToMem ./internal/content -fuzztime=30s
	@echo "Fuzzing FuzzSanitizeTarPath..."
	go test -fuzz=FuzzSanitizeTarPath ./internal/content -fuzztime=30s
	@echo "Fuzzing FuzzExtractClientAddr..."
	go test -fuzz=FuzzExtractClientAddr ./internal/httpmw -fuzztime=30s
	@echo "Fuzzing FuzzHasDotSegments..."
	go test -fuzz=FuzzHasDotSegments ./internal/pathutil -fuzztime=30s
	@echo "Fuzzing FuzzResolvePath..."
	go test -fuzz=FuzzResolvePath ./internal/sitehandler -fuzztime=30s

lint:
	golangci-lint cache clean
	golangci-lint run --disable errcheck --disable staticcheck --disable goconst --disable revive ./...

cover:
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	@go tool cover -func=coverage.out | awk '/^total:/ { gsub(/%/, "", $$NF); if ($$NF+0 < 70) { printf "FAIL: total coverage %s%% is below threshold 70%%\n", $$NF; exit 1 } else { printf "OK: total coverage %s%% meets threshold 70%%\n", $$NF } }'
	@rm coverage.out

clean:
	rm -rf bin/

check: tidy vet lint cover

tidy:
	go mod tidy
	git diff --exit-code go.mod go.sum

release:
	/build-system/build.sh --repo . --ref HEAD --track stable