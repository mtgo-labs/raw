.PHONY: bench check docs fmt fuzz generate lint race test

fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -d .; exit 1; }
	go run ./cmd/doccheck

docs:
	go run ./cmd/doccheck

generate:
	go generate ./...

test:
	go test ./...

race:
	go test -race ./...

lint:
	go vet ./...
	staticcheck ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

fuzz:
	go test -run '^$$' -fuzz=FuzzDecoderBytes           -fuzztime=1s ./tl
	go test -run '^$$' -fuzz=FuzzDecoderVectorHeader     -fuzztime=1s ./tl
	go test -run '^$$' -fuzz=FuzzDecodeGenerated         -fuzztime=1s ./tl
	go test -run '^$$' -fuzz=FuzzDecodeGeneratedResult   -fuzztime=1s ./tl
	go test -run '^$$' -fuzz=FuzzDecodeGzipPacked        -fuzztime=1s ./tl
	go test -run '^$$' -fuzz=FuzzAESIGERoundTrip         -fuzztime=1s ./internal/cryptoutil
	go test -run '^$$' -fuzz=FuzzValidateDHParams        -fuzztime=1s ./internal/cryptoutil
	go test -run '^$$' -fuzz=FuzzMessageDerivation       -fuzztime=1s ./internal/cryptoutil
	go test -run '^$$' -fuzz=FuzzFactorPQ                -fuzztime=1s ./internal/cryptoutil
	go test -run '^$$' -fuzz=FuzzEncryptRSAPadded        -fuzztime=1s ./internal/cryptoutil
	go test -run '^$$' -fuzz=FuzzRouteInboundContainer   -fuzztime=1s ./internal/mtproto
	go test -run '^$$' -fuzz=FuzzDecryptMessage          -fuzztime=1s ./internal/mtproto
	go test -run '^$$' -fuzz=FuzzReadAbridged            -fuzztime=1s ./internal/transport
	go test -run '^$$' -fuzz=FuzzReadIntermediate        -fuzztime=1s ./internal/transport
	go test -run '^$$' -fuzz=FuzzReadPaddedIntermediate  -fuzztime=1s ./internal/transport
	go test -run '^$$' -fuzz=FuzzReadPlain               -fuzztime=1s ./internal/transport
	go test -run '^$$' -fuzz=FuzzDecodeSnapshot          -fuzztime=1s ./session
	go test -run '^$$' -fuzz=FuzzNew                     -fuzztime=1s ./tgerr

check: fmt generate docs test race lint
