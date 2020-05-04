

.PHONY: build test release

build:

release: build
	go build -o pqswcfg config/main/main.go

