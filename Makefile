

.PHONY: build test release

build:

release: build test
	go build -o pqswcfg config/main/main.go

test:
	go test ./...
