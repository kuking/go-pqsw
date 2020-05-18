

.PHONY: clean build test release

all: clean release coverage

clean:
	go clean -testcache -cache
	rm -f bin/pqswcfg*
	rm -f bin/pqswtun*

build:
	go build ./...

release: build test
	go build -o bin/pqswcfg config/main/main.go
	go build -o bin/pqswtun	tunnel/main/main.go

rpi: release
	GOOS=linux GOARCH=arm	go build -o bin/pqswcfg-linux-arm config/main/main.go
	GOOS=linux GOARCH=arm	go build -o bin/pqswtun-linux-arm tunnel/main/main.go

osx: release
	GOOS=darwin GOARCH=amd64	go build -o bin/pqswcfg-darwin-amd64 config/main/main.go
	GOOS=darwin GOARCH=amd64	go build -o bin/pqswtun-darwin-amd64 tunnel/main/main.go

win: release
	GOOS=windows GOARCH=amd64	go build -o bin/pqswcfg-win-amd64.exe config/main/main.go
	GOOS=windows GOARCH=amd64	go build -o bin/pqswtun-win-amd64.exe tunnel/main/main.go

test:
	go test ./...

coverage:
	go test -cover -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
