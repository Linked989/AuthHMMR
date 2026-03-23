.PHONY: run generate register auth detail

GO ?= go

run: generate register auth

generate:
	$(GO) run ./cmd/generate-devices

register:
	$(GO) run ./cmd/reg

auth:
	$(GO) run ./cmd/auth

detail:
	$(GO) run ./cmd/detail-dev

query:
	$(GO) run ./cmd/query-devices

clear:
	$(GO) run ./cmd/clear-devices
