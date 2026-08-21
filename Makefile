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

# ------------------------------------------------------------- setting up and updating
#
# Two entry points that stand in front of everything below. `wizard` is the one that adds
# or removes pieces, and asks before each; `reload` is the one to run after editing code,
# which asks nothing and installs nothing — it rebuilds and restarts what is already
# there. Neither replaces the individual targets; both are made of them.
#
# Both choose their own configuration and ignore CONFIG, unlike every other target here:
# what they build has to match what is already installed, which they can see and a
# variable default cannot. Override with BEHOLDER_CONFIG, the same name install-daemon.sh
# has always used.

.PHONY: wizard
wizard: ## Install or update, asking about each piece (run this first)
	./Scripts/wizard.sh

.PHONY: reload
reload: ## Rebuild and restart everything that is running (run this after editing)
	./Scripts/reload.sh

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

.PHONY: test-socket
test-socket: ## Check the publishing socket keeps its framing and survives readers leaving
	./Scripts/test-publishing-socket.sh

.PHONY: test-pf
test-pf: ## Check blocking is off by default and prints a clean ruleset
	./Scripts/test-pf-anchor.sh

.PHONY: test-control
test-control: ## Check the control socket admits only the pinned program
	./Scripts/test-control-socket.sh

.PHONY: check
check: ## Build and test, failing on any warning
	@swift build --configuration $(CONFIG) 2>&1 | tee /tmp/beholder-build.log
	@if grep -q "warning:" /tmp/beholder-build.log; then \
		echo "Build produced warnings."; exit 1; \
	fi
	@swift test
	@./Scripts/test-publishing-socket.sh
	@./Scripts/test-mcp-stdio.sh
	@./Scripts/test-pf-anchor.sh
	@./Scripts/test-control-socket.sh

# ------------------------------------------------------------------------- running

.PHONY: run
run: build ## (root) Start capture and open the app. Ctrl-C stops both
	./beholder

.PHONY: serve
serve: daemon-bin ## (root) Capture and publish for the app, drawing nothing
	sudo $(DAEMON) --serve --loopback

.PHONY: cleartext
cleartext: daemon-bin ## (root) Capture and publish, also reading unencrypted payload
	sudo $(DAEMON) --serve --loopback --read-cleartext

.PHONY: top
top: daemon-bin ## (root) Live connection table in the terminal
	sudo $(DAEMON) --top --loopback

.PHONY: stats
stats: daemon-bin ## (root) Per-interface capture statistics
	sudo $(DAEMON) --loopback

.PHONY: open-app
open-app: app ## Open the app against an already-running daemon
	open $(APP)

# ------------------------------------------------------------------------- blocking

# The one thing Beholder does that changes what this machine can reach. Separate from
# everything above, and from `make install`, because capturing and blocking are different
# decisions - installing the daemon should not quietly arm a firewall.

.PHONY: pf-install
pf-install: daemon-bin ## (root) Install the pf anchor, so --block has something to fill
	sudo ./Scripts/install-pf-anchor.sh

.PHONY: pf-uninstall
pf-uninstall: ## (root) Remove the pf anchor. Your block list is left alone
	sudo ./Scripts/uninstall-pf-anchor.sh

.PHONY: control-pin
control-pin: app ## (root) Pin the app's identity, so it may change what is blocked
	sudo ./Scripts/install-control-pin.sh

.PHONY: control-status
control-status: daemon-bin ## Report whether the pinned peer identity can be loaded
	@$(DAEMON) --check-control-pin

.PHONY: block
block: daemon-bin ## (root) Capture, publish, and block what the block list names
	sudo $(DAEMON) --serve --loopback --block

.PHONY: install-blocking
install-blocking: ## (root) Make the installed daemon enforce the block list, across reboots
	sudo ./Scripts/install-daemon.sh --block

.PHONY: uninstall-blocking
uninstall-blocking: ## (root) Stop the installed daemon enforcing anything
	sudo ./Scripts/install-daemon.sh --no-block

.PHONY: check-blocklist
check-blocklist: daemon-bin ## Show what the block list would block, changing nothing
	@$(DAEMON) --check-blocklist

# /sbin/pfctl absolutely, never `pfctl` off PATH. These run under sudo, and resolving a
# program name through PATH in a root shell is the thing the daemon's own spawner is
# careful to avoid; the Makefile should not be the loose end.
.PHONY: block-status
block-status: ## Show what pf is blocking for Beholder right now
	@echo "Rules:"
	@sudo /sbin/pfctl -a com.beholder -s rules 2>/dev/null | sed 's/^/  /' || echo "  anchor not loaded"
	@echo "Blocking:"
	@sudo /sbin/pfctl -a com.beholder -t beholder_blocked -T show 2>/dev/null | sed 's/^/  /' || echo "  nothing"

.PHONY: unblock
unblock: ## (root) Stop blocking everything, now. The escape hatch
	@sudo /sbin/pfctl -a com.beholder -t beholder_blocked -T flush 2>/dev/null \
		&& echo "Block table emptied." \
		|| echo "Nothing to empty - the anchor is not loaded."

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

# ------------------------------------------------------------------ classification

.PHONY: trackers
trackers: ## Download the tracker ownership index (DuckDuckGo, CC BY-NC-SA 4.0)
	./Scripts/fetch-trackers.sh

.PHONY: trackers-status
trackers-status: ## Report whether the tracker index is installed
	@for p in /usr/local/share/beholder/trackers.json Resources/trackers/trackers.json; do \
		if [ -f "$$p" ]; then echo "installed: $$p ($$(du -h $$p | cut -f1))"; exit 0; fi; \
	done; echo "not installed - run 'make trackers'"

.PHONY: data
data: geoip trackers ## Download both optional databases

# ---------------------------------------------------------------------- diagnostics

.PHONY: doctor
doctor: ## Diagnose why the app cannot see the daemon
	@# The script's exit code says whether it found a fault, which is useful when
	@# scripting it but only adds a bare "Error 1" under the diagnosis it just printed.
	@./Scripts/doctor.sh || true

.PHONY: restart
restart: ## (root) Restart the installed daemon as it is — see 'reload' after an edit
	@# This restarts /usr/local/libexec/beholderd, which is a copy taken at install time.
	@# After editing code you want 'reload', which replaces that copy first; this target
	@# would faithfully restart the old build.
	sudo launchctl kickstart -k system/com.beholder.daemon
	@sleep 1
	@$(MAKE) --no-print-directory doctor

# ------------------------------------------------------------------------- history

.PHONY: history
history: daemon-bin ## Show what was captured in the last day (no root needed)
	@$(DAEMON) --history

.PHONY: history-week
history-week: daemon-bin ## Show the last week
	@$(DAEMON) --history --hours 168

.PHONY: history-csv
history-csv: daemon-bin ## Export the last day as CSV
	@$(DAEMON) --history --csv

# ----------------------------------------------------------------- asking questions

.PHONY: mcp
mcp: ## Build the MCP server, so an assistant can be asked about the history
	swift build --configuration $(CONFIG) --product BeholderMCP

.PHONY: mcp-add
mcp-add: mcp ## Print the command that registers the MCP server with Claude
	@# Printed rather than run. Registering a server in someone's assistant configuration
	@# is their decision, and a target that quietly edited it would be the one surprising
	@# thing in a Makefile that otherwise only touches this directory.
	@echo "Register the MCP server by running:"
	@echo
	@echo "  claude mcp add beholder -- $(abspath $(BUILD))/BeholderMCP"
	@echo
	@echo "Then ask: \"is Beholder recording anything?\""
	@echo "Remove it again with: claude mcp remove beholder"

.PHONY: mcp-install
mcp-install: mcp ## (root) Install the MCP server to /usr/local/libexec
	@# The install and the registration guidance live in the script, not here, so that
	@# the wizard and reload print the same advice rather than their own copy of it.
	sudo env BEHOLDER_CONFIG=$(CONFIG) BEHOLDER_SKIP_BUILD=1 ./Scripts/install-mcp.sh

.PHONY: test-mcp
test-mcp: mcp ## Check the MCP server's stdout carries nothing but protocol
	./Scripts/test-mcp-stdio.sh

# ------------------------------------------------------- continuous capture (root)

.PHONY: install
install: ## (root) Install as a launchd daemon so it captures continuously and at boot
	sudo ./Scripts/install-daemon.sh

.PHONY: uninstall
uninstall: ## (root) Remove the daemon. Your captured history is left alone
	sudo ./Scripts/uninstall-daemon.sh

.PHONY: status
status: ## Report whether the installed daemon is running
	@if launchctl print system/com.beholder.daemon >/dev/null 2>&1; then \
		echo "running (installed as a launchd daemon)"; \
	elif [ -S /var/run/beholder.sock ]; then \
		echo "running in the foreground"; \
	else \
		echo "not running"; \
	fi

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
