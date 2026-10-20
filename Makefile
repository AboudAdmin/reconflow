.PHONY: build test vet fmt linux
build:
	go build -o reconflow ./cmd/reconflow
linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/reconflow-linux-amd64 ./cmd/reconflow
test:
	go test ./...
vet:
	go vet ./...
fmt:
	gofmt -l -w .
