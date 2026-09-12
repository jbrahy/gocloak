.PHONY: test lint fuzz vuln build

test:
	go test -race ./...

lint:
	go vet ./...
	staticcheck ./...

fuzz:
	go test -fuzz=FuzzHelloFrame -fuzztime=60s .

vuln:
	govulncheck ./...

build:
	go build -o bin/gocloak ./cmd/gocloak
	go build -o bin/gocloak-sink ./cmd/gocloak-sink
	go build -o bin/gocloak-send ./cmd/gocloak-send
