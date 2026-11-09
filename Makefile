# SPDX-License-Identifier: GPL-2.0-or-later
# Alcyon Load Balancer Makefile
# Copyright (C) 2000-2026 Willy Tarreau and Alcyon contributors. See LICENSE.

SHELL := /bin/bash

# Standard Unix directory and toolchain variables
PREFIX           ?= /usr/local
BINDIR           ?= $(PREFIX)/bin
DESTDIR          ?=
CARGO            ?= cargo
CARGO_FLAGS      ?= --release
PYTHON           ?= python3

# Target binaries and configurations
TARGET_DIR       := target
TARGET_RELEASE   := $(TARGET_DIR)/release/alcyon
TARGET_DEBUG     := $(TARGET_DIR)/debug/alcyon
CANONICAL_CONFIG ?= examples/canonical_haproxy_35.cfg
STATS_CONFIG     ?= examples/stats_dashboard.cfg
RUN_FLAGS        ?=

# Test reference oracles and suites: under $(ALCYON_REFERENCE) (README, "Running the oracle
# tests"). Without it, `test` and `lint` leave out alcyon-h1-sys (it compiles HAProxy's C) and
# the oracle targets stop, naming the variable.
WORKSPACE        := $(if $(ALCYON_REFERENCE),--workspace,)
NEED_REFERENCE    = @test -n "$(ALCYON_REFERENCE)" || { echo "set ALCYON_REFERENCE to the directory of the reference HAProxy builds (README, 'Running the oracle tests')" >&2; exit 1; }
DIFFTEST_REF     ?= $(ALCYON_REFERENCE)/haproxy-1.0.2/haproxy102
DIFFTEST_EXTRA   ?=
VTC_TEST         ?= $(ALCYON_REFERENCE)/haproxy/reg-tests/balance/balance-rr.vtc
VTC_ALL_TESTS    ?= $(ALCYON_REFERENCE)/haproxy/reg-tests/balance/balance-rr.vtc
VTC_EXTRA        ?=

# Installation commands
INSTALL          ?= install
INSTALL_PROGRAM  ?= $(INSTALL) -m 755
INSTALL_DIR      ?= $(INSTALL) -d -m 755
RM               ?= rm -f
RMDIR            ?= rm -rf

# Terminal styling for help and banner display
BOLD             := \033[1m
GREEN            := \033[1;32m
CYAN             := \033[1;36m
YELLOW           := \033[1;33m
MAGENTA          := \033[1;35m
RESET            := \033[0m

.PHONY: all build debug test lint check fmt fmt-check difftest difftest-candidate vtc vtc-all run run-stats install uninstall clean help FORCE

##@ Build Targets

all: build ## Build release binary (default target)

build: $(TARGET_RELEASE) ## Build release binary (target/release/alcyon)

debug: $(TARGET_DEBUG) ## Build debug binary (target/debug/alcyon)

$(TARGET_RELEASE): FORCE
	@echo -e "$(CYAN)Building Alcyon release binary ($(TARGET_RELEASE))...$(RESET)"
	$(CARGO) build $(CARGO_FLAGS) --workspace --bin alcyon

$(TARGET_DEBUG): FORCE
	@echo -e "$(CYAN)Building Alcyon debug binary ($(TARGET_DEBUG))...$(RESET)"
	$(CARGO) build --workspace --bin alcyon

##@ Testing & Verification

test: ## Run all workspace tests ($(CARGO) test, --workspace when ALCYON_REFERENCE is set)
	@echo -e "$(GREEN)Running full workspace test suite...$(RESET)"
	$(CARGO) test $(WORKSPACE)

difftest: ## Run differential test harness against reference HAProxy
	@echo -e "$(GREEN)Running differential testing harness against reference HAProxy...$(RESET)"
	$(NEED_REFERENCE)
	$(PYTHON) harness/difftest.py --reference $(DIFFTEST_REF) $(DIFFTEST_EXTRA)

difftest-candidate: build ## Run differential test harness comparing reference vs candidate (alcyon)
	@echo -e "$(GREEN)Running differential test comparison (reference vs candidate)...$(RESET)"
	$(NEED_REFERENCE)
	$(PYTHON) harness/difftest.py --reference $(DIFFTEST_REF) --candidate $(TARGET_RELEASE) $(DIFFTEST_EXTRA)

vtc: debug ## Run VTC runner on HAProxy regression tests (balance-rr.vtc)
	@echo -e "$(GREEN)Running VTC regression test runner...$(RESET)"
	$(NEED_REFERENCE)
	$(PYTHON) harness/vtc_runner.py $(VTC_TEST) $(VTC_EXTRA)

vtc-all: debug ## Run VTC runner on all compatible regression tests
	@echo -e "$(GREEN)Running all compatible VTC regression tests...$(RESET)"
	$(NEED_REFERENCE)
	$(PYTHON) harness/vtc_runner.py $(VTC_ALL_TESTS) $(VTC_EXTRA)

##@ Code Quality & Formatting

lint: ## Run strict linter ($(CARGO) clippy --all-targets -- -D warnings; --workspace with ALCYON_REFERENCE)
	@echo -e "$(YELLOW)Running Clippy strict linter across all workspace crates...$(RESET)"
	$(CARGO) clippy $(WORKSPACE) --all-targets -- -D warnings

check: lint ## Run strict linter (alias for lint)

fmt: ## Format Rust source files ($(CARGO) fmt --all)
	@echo -e "$(CYAN)Formatting all Rust source files...$(RESET)"
	$(CARGO) fmt --all

fmt-check: ## Check formatting without modifying files
	@echo -e "$(CYAN)Checking formatting across workspace...$(RESET)"
	$(CARGO) fmt --all -- --check

##@ Execution & Operations

run: build ## Run alcyon with examples/canonical_haproxy_35.cfg
	@echo -e "$(GREEN)Running Alcyon with $(CANONICAL_CONFIG)...$(RESET)"
	./$(TARGET_RELEASE) -f $(CANONICAL_CONFIG) $(RUN_FLAGS)

run-stats: debug ## Run alcyon with modern Web Stats Dashboard on port 8404
	@echo -e "$(GREEN)Starting Alcyon Stats Dashboard on http://127.0.0.1:8404/stats ...$(RESET)"
	./$(TARGET_DEBUG) -f $(STATS_CONFIG) $(RUN_FLAGS)

smoke: debug ## Run end-to-end HTTPS/TLS smoke test with curl and Nginx on port 8443
	@echo -e "$(GREEN)Running end-to-end TLS smoke test on https://localhost:8443/ ...$(RESET)"
	$(PYTHON) harness/smoke_nginx_8443.py

##@ Installation & Packaging

install: build ## Install alcyon binary into $(DESTDIR)$(PREFIX)/bin/alcyon (mode 755)
	@echo -e "$(GREEN)Installing $(TARGET_RELEASE) into $(DESTDIR)$(BINDIR)/alcyon...$(RESET)"
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	$(INSTALL_PROGRAM) $(TARGET_RELEASE) $(DESTDIR)$(BINDIR)/alcyon

uninstall: ## Remove $(DESTDIR)$(PREFIX)/bin/alcyon
	@echo -e "$(YELLOW)Removing $(DESTDIR)$(BINDIR)/alcyon...$(RESET)"
	$(RM) $(DESTDIR)$(BINDIR)/alcyon

##@ Cleanup & Help

clean: ## Remove target/ and temporary artifacts
	@echo -e "$(YELLOW)Cleaning workspace build artifacts...$(RESET)"
	$(CARGO) clean
	$(RMDIR) $(TARGET_DIR)
	$(RM) harness/*.json harness/__pycache__/*.pyc
	$(RMDIR) harness/__pycache__
	$(RM) /tmp/alcyon.sock /tmp/alcyon-test*.sock

help: ## Display this styled self-documenting help menu
	@echo -e "$(CYAN)======================================================================$(RESET)"
	@echo -e "$(CYAN)  Alcyon High-Performance Load Balancer — Build Automation System       $(RESET)"
	@echo -e "$(CYAN)======================================================================$(RESET)"
	@echo -e "$(BOLD)Usage:$(RESET) make $(GREEN)<target>$(RESET) [$(YELLOW)VARIABLE=value$(RESET)]"
	@awk 'BEGIN {FS = ":.*?## "}; \
		/^##@/ { printf "\n\033[1;33m%s\033[0m\n", substr($$0, 5) } \
		/^[a-zA-Z0-9_-]+:.*?## / { printf "  \033[1;32m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo -e "\n$(YELLOW)Configurable Variables:$(RESET)"
	@echo -e "  $(MAGENTA)PREFIX$(RESET)             Install destination prefix (default: $(CYAN)$(PREFIX)$(RESET))"
	@echo -e "  $(MAGENTA)DESTDIR$(RESET)            Staging root directory for packaging (default: $(CYAN)$(DESTDIR)$(RESET))"
	@echo -e "  $(MAGENTA)CARGO$(RESET)              Cargo executable (default: $(CYAN)$(CARGO)$(RESET))"
	@echo -e "  $(MAGENTA)CARGO_FLAGS$(RESET)        Flags passed to cargo build (default: $(CYAN)$(CARGO_FLAGS)$(RESET))"
	@echo -e "  $(MAGENTA)PYTHON$(RESET)             Python executable for test harnesses (default: $(CYAN)$(PYTHON)$(RESET))"
	@echo -e "  $(MAGENTA)DIFFTEST_REF$(RESET)       Reference HAProxy 1.0.2 binary path (default: $(CYAN)$(DIFFTEST_REF)$(RESET))"
	@echo -e "  $(MAGENTA)VTC_TEST$(RESET)           Primary regression test file (default: $(CYAN)$(VTC_TEST)$(RESET))"
	@echo -e "  $(MAGENTA)CANONICAL_CONFIG$(RESET)   Configuration file for 'make run' (default: $(CYAN)$(CANONICAL_CONFIG)$(RESET))"
	@echo -e "$(CYAN)======================================================================$(RESET)"
