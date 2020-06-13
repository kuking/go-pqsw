
PQSWCFG_MAIN = cli/pqswcfg/main.go
PQSWCFG_BIN = bin/pqswcfg

PQSWTUN_MAIN = cli/pqswtun/main.go
PQSWTUN_BIN = bin/pqswtun

all: clean build test bench release coverage

clean:
	go clean -testcache -cache
	rm -f $(PQSWCFG_BIN)*
	rm -f $(PQSWTUN_BIN)*

build:
	go build ./...

release: build test
	go build -o $(PQSWCFG_BIN) $(PQSWCFG_MAIN)
	go build -o $(PQSWTUN_BIN) $(PQSWTUN_MAIN)

rpi: release
	GOOS=linux GOARCH=arm	go build -o $(PQSWCFG_BIN)-linux-arm $(PQSWCFG_MAIN)
	GOOS=linux GOARCH=arm	go build -o $(PQSWTUN_BIN)-linux-arm $(PQSWTUN_MAIN)

osx: release
	GOOS=darwin GOARCH=amd64	go build -o $(PQSWCFG_BIN)-darwin-amd64 $(PQSWCFG_MAIN)
	GOOS=darwin GOARCH=amd64	go build -o $(PQSWTUN_BIN)-darwin-amd64 $(PQSWTUN_MAIN)

win: release
	GOOS=windows GOARCH=amd64	go build -o $(PQSWCFG_BIN)-win-amd64.exe $(PQSWCFG_MAIN)
	GOOS=windows GOARCH=amd64	go build -o $(PQSWTUN_BIN)-win-amd64.exe $(PQSWTUN_MAIN)

test:
	go test ./...

bench:
	go test ./... -run=Benchmark -bench=. -benchmem

coverage:
	go test -cover -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
