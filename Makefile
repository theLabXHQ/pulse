# Reproducible builds: no cgo, trimmed paths, no VCS stamping, fixed version.
VERSION ?= 0.1.0
PKG      = github.com/theLabXHQ/pulse
LDFLAGS  = -s -w -buildid= -X $(PKG)/internal/version.Version=$(VERSION)
GOFLAGS  = -trimpath -buildvcs=false
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build test race vet dist checksums clean
build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o pulse ./cmd/pulse

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

dist:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o dist/pulse_$(VERSION)_$${os}_$${arch}$$ext ./cmd/pulse || exit 1; \
	done
	@cd dist && sha256sum pulse_* > SHA256SUMS && cat SHA256SUMS

clean:
	rm -rf dist pulse
