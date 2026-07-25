.PHONY: bench check docs fmt lint race test

fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -d .; exit 1; }
	go run ./cmd/doccheck

docs:
	go run ./cmd/doccheck

test:
	go test ./...

race:
	go test -race ./...

lint:
	go vet ./...
	staticcheck ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

check: fmt docs test race lint
