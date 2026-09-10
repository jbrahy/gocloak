.PHONY: test lint fuzz vuln

test:
	go test -race ./...

lint:
	go vet ./...
	staticcheck ./...

fuzz:
	go test -fuzz=FuzzHelloFrame -fuzztime=60s .

vuln:
	govulncheck ./...
