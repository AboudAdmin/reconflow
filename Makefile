.PHONY: build test vet fmt linux dashboard
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

# Rebuild the embedded React dashboard (needs Node; the built file is committed so Go-only builds work).
dashboard:
	cd dashboard && npm install && npm run build && cp dist/index.html ../internal/reporting/dashboard.html
