

.PHONY: clean build test release

clean:
	go clean -testcache -cache
	rm -f bin/pqswcfg

build:

release: build test
	go build -o bin/pqswcfg config/main/main.go

test:
	go test ./...
