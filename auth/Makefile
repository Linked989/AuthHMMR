.PHONY: run generate register auth detail

GO ?= go

run: generate register auth

generate:
	$(GO) run generate_devices.go

register:
	$(GO) run reg.go

auth:
	$(GO) run auth.go

detail:
	$(GO) run detail_dev.go
