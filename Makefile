# DNSid cross-SDK compliance test kit.
# SDK checkouts default to sibling directories of the dnsid repo; override:
#   make run DNSID_TS_DIR=/path/to/dnsid-ts
DNSID_GO_DIR ?= $(HOME)/dnsid-go
DNSID_TS_DIR ?= $(HOME)/dnsid-ts
DNSID_PY_DIR ?= $(HOME)/dnsid-py
export DNSID_GO_DIR DNSID_TS_DIR DNSID_PY_DIR

.PHONY: setup run c2sp-matrix clean ts-build

setup: shims/go/dnsid-shim ts-build .venv

shims/go/dnsid-shim: shims/go/*.go shims/go/go.mod
	cd shims/go && rm -f go.work go.work.sum && \
		go work init . "$(DNSID_GO_DIR)" && \
		go build -o dnsid-shim .

ts-build:
	cd "$(DNSID_TS_DIR)" && npm ci --silent && npm run build --silent

.venv:
	uv venv .venv
	uv pip install -p .venv pyyaml cryptography -e "$(DNSID_PY_DIR)"

run: setup
	.venv/bin/python harness/c2sp_event_identity_check.py
	.venv/bin/python harness/run.py --out report.md

c2sp-matrix: ts-build .venv
	cd shims/go && rm -f go.work go.work.sum && go work init . "$(DNSID_GO_DIR)"
	.venv/bin/python harness/c2sp_matrix.py

clean:
	rm -rf .venv shims/go/dnsid-shim shims/go/go.work shims/go/go.work.sum report.md
