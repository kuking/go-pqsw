

.PHONY: clean build test release

clean:
	go clean -testcache -cache
	rm -f bin/pqswcfg
	rm -f bin/pqswtun

clean-rpi:
	go clean -testcache -cache
	rm -f bin/pqswcfg-linux-arm
	rm -f bin/pqswtun-linux-arm

build:

release: build test
	go build -o bin/pqswcfg config/main/main.go
	go build -o bin/pqswtun	tunnel/main/main.go

release-rpi: build test
	GOOS=linux GOARCH=arm go build -o bin/pqswcfg-linux-arm config/main/main.go
	GOOS=linux GOARCH=arm go build -o bin/pqswtun-linux-arm tunnel/main/main.go

test:
	go test ./...
