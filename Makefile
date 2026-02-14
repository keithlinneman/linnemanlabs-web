.PHONY: build run test clean release

build:
	go build -o bin/linnemanlabs-web ./cmd/server

run: build
	./bin/linnemanlabs-web

test:
	go test ./...

clean:
	rm -rf bin/

release:
	/build-system/build.sh --repo . --ref HEAD --track stable