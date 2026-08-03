# Beholder
#
# Targets marked (root) will ask for your password: packet capture reads /dev/bpf*,
# which is mode 0600 root:wheel. Everything else runs as you.
#
# `make help` lists everything.

CONFIG ?= debug
BUILD  := .build/$(CONFIG)
DAEMON := $(BUILD)/beholderd
APP    := .build/Beholder.app
LOGS   := logs

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------- build

.PHONY: build
build: ## Build the daemon and the app
	swift build --configuration $(CONFIG)
	./Scripts/build-app.sh $(CONFIG)

.PHONY: daemon-bin
daemon-bin: ## Build only the daemon
	swift build --configuration $(CONFIG) --product beholderd

.PHONY: app
app: ## Build the app bundle
	./Scripts/build-app.sh $(CONFIG)

.PHONY: test
test: ## Run the test suite
	swift test

.PHONY: check
check: ## Build and test, failing on any warning
	@swift build --configuration $(CONFIG) 2>&1 | tee /tmp/beholder-build.log
	@if grep -q "warning:" /tmp/beholder-build.log; then \
		echo "Build produced warnings."; exit 1; \
	fi
	@swift test

# ------------------------------------------------------------------------- running

.PHONY: run
run: build ## (root) Start capture and open the app. Ctrl-C stops both
	./beholder

.PHONY: serve
serve: daemon-bin ## (root) Capture and publish for the app, drawing nothing
	sudo $(DAEMON) --serve --loopback

.PHONY: top
top: daemon-bin ## (root) Live connection table in the terminal
	sudo $(DAEMON) --top --loopback

.PHONY: stats
stats: daemon-bin ## (root) Per-interface capture statistics
	sudo $(DAEMON) --loopback

.PHONY: open-app
open-app: app ## Open the app against an already-running daemon
	open $(APP)

# --------------------------------------------------------------- no root required

.PHONY: sockets
sockets: daemon-bin ## Dump the socket-to-process table (compare against lsof)
	$(DAEMON) --sockets

.PHONY: selftest
selftest: daemon-bin ## Exercise timers, rendering and shutdown without capturing
	$(DAEMON) --top --self-test

.PHONY: route
route: daemon-bin ## Show which interface currently carries the default route
	@route -n get default 2>/dev/null | grep -E "interface|gateway" || echo "no default route"

# ----------------------------------------------------------------------- geolocation

.PHONY: geoip
geoip: ## Download the DB-IP City Lite database (~124 MB, CC BY 4.0)
	./Scripts/fetch-geoip.sh

.PHONY: geoip-status
geoip-status: ## Report whether a geolocation database is installed
	@for p in /usr/local/share/beholder/geoip.mmdb Resources/geoip/geoip.mmdb; do \
		if [ -f "$$p" ]; then echo "installed: $$p ($$(du -h $$p | cut -f1))"; exit 0; fi; \
	done; echo "not installed - run 'make geoip'"

# ------------------------------------------------------------------------ evidence

.PHONY: log
log: ## Print the path of the most recent run transcript
	@if [ -L $(LOGS)/latest.log ]; then \
		echo "$(LOGS)/latest.log -> $$(readlink $(LOGS)/latest.log)"; \
	else \
		echo "No transcript yet. Run 'make run' or 'make top' first."; \
	fi

.PHONY: report
report: ## Show the final report from the most recent run
	@if [ -f $(LOGS)/latest.log ]; then \
		awk '/^FINAL REPORT$$/{found=NR} {a[NR]=$$0} END{if(found){for(i=found-1;i<=NR;i++) print a[i]} else print "No final report yet — the run may still be going."}' $(LOGS)/latest.log; \
	else \
		echo "No transcript yet. Run 'make run' or 'make top' first."; \
	fi

.PHONY: tail
tail: ## Follow the most recent transcript as it is written
	@test -f $(LOGS)/latest.log || { echo "No transcript yet."; exit 1; }
	tail -f $(LOGS)/latest.log

# --------------------------------------------------------------------- maintenance

.PHONY: stop
stop: ## (root) Stop any running capture daemon
	@sudo pkill -INT -f "$(DAEMON)" 2>/dev/null && echo "Stopped." || echo "No daemon running."

.PHONY: clean
clean: ## Remove build products (transcripts are left alone)
	rm -rf .build

.PHONY: clean-logs
clean-logs: ## Delete every run transcript
	rm -rf $(LOGS)

.PHONY: help
help: ## List these targets
	@echo "Beholder — targets marked (root) will ask for your password."
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}'
