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

.PHONY: test-server
test-server: ## Check that a departing reader cannot kill the daemon (needs no root)
	./Scripts/test-server-resilience.sh

.PHONY: check
check: ## Build and test, failing on any warning
	@swift build --configuration $(CONFIG) 2>&1 | tee /tmp/beholder-build.log
	@if grep -q "warning:" /tmp/beholder-build.log; then \
		echo "Build produced warnings."; exit 1; \
	fi
	@swift test
	@./Scripts/test-server-resilience.sh

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
	@echo "Daemon process:"
	@ps -Ao pid,lstart,command | grep -E "(libexec/)?beholderd --serve" | grep -v grep \
		|| echo "  not running"
	@echo
	@echo "launchd job:"
	@launchctl print system/com.beholder.daemon 2>/dev/null \
		| grep -E "^\s*(state|pid|runs|last exit code) " || echo "  not installed"
	@echo
	@echo "Publishing socket:"
	@if [ -S /var/run/beholder.sock ]; then \
		ls -la /var/run/beholder.sock; \
		if python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect('/var/run/beholder.sock')" 2>/dev/null; then \
			echo "  accepting connections - healthy"; \
		else \
			echo "  PRESENT BUT REFUSING CONNECTIONS - stale socket, restart the daemon:"; \
			echo "    sudo launchctl kickstart -k system/com.beholder.daemon"; \
		fi; \
	else \
		echo "  no socket at /var/run/beholder.sock"; \
	fi
	@echo
	@echo "Recent daemon output:"
	@tail -5 /var/log/beholderd.log 2>/dev/null || echo "  (none)"
	@tail -5 /var/log/beholderd.err 2>/dev/null
	@echo
	@if launchctl print system/com.beholder.daemon 2>/dev/null | grep -q "runs = "; then \
		if ! pgrep -f "libexec/beholderd" >/dev/null 2>&1; then \
			if [ ! -s /var/log/beholderd.log ] && [ ! -s /var/log/beholderd.err ]; then \
				echo "The job is loaded but has never actually run: no process, and both"; \
				echo "logs are empty. macOS registers daemons from unidentified developers"; \
				echo "and refuses to start them until you approve them:"; \
				echo; \
				echo "  System Settings > General > Login Items & Extensions"; \
				echo "  find Beholder and turn it on."; \
				echo; \
				echo "Opening that pane now..."; \
				open "x-apple.systempreferences:com.apple.LoginItems-Settings.extension" 2>/dev/null || true; \
			fi; \
		fi; \
	fi

.PHONY: restart
restart: ## (root) Restart the installed daemon
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
