# Simple, cross-platform release Makefile for JLDAP

APP       := jldap
MODULE    := ./...
BUILD_DIR := dist

# --------------------------------------------------------------------
# OS / archive / shell detection (Windows vs POSIX)
# --------------------------------------------------------------------

ifeq ($(OS),Windows_NT)
	ARCHIVE_EXT := zip
	SHELL       := cmd.exe
	.SHELLFLAGS := /C
	NULLDEV     := NUL
	EXE_EXT     := .exe       # for native build name only
	# mkdir / rm that work under cmd.exe
	MKDIR_DIST  = if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"
	RM_DIST     = if exist "$(BUILD_DIR)" rmdir /S /Q "$(BUILD_DIR)"
else
	ARCHIVE_EXT := tar.gz
	# default SHELL is /bin/sh
	NULLDEV     := /dev/null
	EXE_EXT     :=
	MKDIR_DIST  = mkdir -p "$(BUILD_DIR)"
	RM_DIST     = rm -rf "$(BUILD_DIR)"
endif

# --------------------------------------------------------------------
# Helpers to split OSARCH like "linux_amd64" into GOOS / GOARCH
# (used only on non-Windows hosts)
# --------------------------------------------------------------------

os   = $(strip $(word 1,$(subst _, ,$1)))
arch = $(strip $(word 2,$(subst _, ,$1)))

# --------------------------------------------------------------------
# Version information from git, can be overridden: make VERSION=1.2.3
# --------------------------------------------------------------------

VERSION ?= $(shell git describe --tags --always --dirty 2>$(NULLDEV) || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>$(NULLDEV) || echo unknown)

# --------------------------------------------------------------------
# Target OS/ARCH combinations
#   - On Unix: build for linux, windows, darwin
#   - On Windows: only build windows_amd64 (native)
# --------------------------------------------------------------------

ifeq ($(OS),Windows_NT)
	OSARCHES := windows_amd64
else
	OSARCHES := linux_amd64 linux_arm64 windows_amd64 windows_arm64 darwin_amd64 darwin_arm64
endif

# Go + build flags
GO             ?= go
GO_BUILD_FLAGS := -trimpath
# Reproducible-ish: strip symbols, no build id, no path info; embed version/commit
GO_LDFLAGS     := -s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all clean release native test lint check single

# --------------------------------------------------------------------
# Build command macro for native build
# --------------------------------------------------------------------

ifeq ($(OS),Windows_NT)

# $(1) = output binary path
define GO_BUILD_NATIVE
	set CGO_ENABLED=0 && $(GO) build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" -o "$(1)" .
endef

else  # POSIX

define GO_BUILD_NATIVE
	CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" -o "$(1)" .
endef

endif

# --------------------------------------------------------------------
# Default: test + lint + build all release archives
# --------------------------------------------------------------------
all: check release

# Run tests
test:
	$(GO) test ./...

# Basic lint (no external tools)
lint:
	$(GO) vet ./...

check: test lint

# --------------------------------------------------------------------
# Git cleanliness guards for RELEASE=1 (POSIX-only)
# --------------------------------------------------------------------

define ensure_clean_git
	@echo "==> Checking Git working tree is clean (RELEASE=1)"
	@if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
		echo "!! Not a git repository. Cannot perform release clean checks."; \
		exit 1; \
	fi
	@if ! git diff --quiet; then \
		echo "!! Uncommitted changes found. Commit or stash before releasing."; \
		git status -s; \
		exit 1; \
	fi
	@if ! git diff --cached --quiet; then \
		echo "!! Staged but not committed changes. Commit them before releasing."; \
		git status -s; \
		exit 1; \
	fi
	@if [ -n "$$(git ls-files --others --exclude-standard)" ]; then \
		echo "!! Untracked files present. Clean working tree required for RELEASE=1."; \
		git ls-files --others --exclude-standard; \
		exit 1; \
	fi
endef

define ensure_clean_version
	@echo "==> Checking VERSION does not contain '-dirty' (RELEASE=1)"
	@if echo "$(VERSION)" | grep -q "dirty"; then \
		echo "!! VERSION '$(VERSION)' contains '-dirty'. Refusing RELEASE build."; \
		exit 1; \
	fi
endef

# NOTE: These blocks use POSIX shell syntax and are only invoked
# on non-Windows hosts below when RELEASE=1.

# --------------------------------------------------------------------
# Directory helper
# --------------------------------------------------------------------

$(BUILD_DIR):
	$(MKDIR_DIST)

# --------------------------------------------------------------------
# Release targets
# --------------------------------------------------------------------

# Build all release archives
release:
ifeq ($(RELEASE),1)
ifneq ($(OS),Windows_NT)
	$(call ensure_clean_git)
	$(call ensure_clean_version)
endif
endif
	$(MAKE) $(OSARCHES:%=$(BUILD_DIR)/$(APP)_$(VERSION)_%.$(ARCHIVE_EXT))

# Build a single OS/ARCH archive: make single OSARCH=linux_amd64
OSARCH ?= linux_amd64
single:
ifeq ($(RELEASE),1)
ifneq ($(OS),Windows_NT)
	$(call ensure_clean_git)
	$(call ensure_clean_version)
endif
endif
	$(MAKE) $(BUILD_DIR)/$(APP)_$(VERSION)_$(OSARCH).$(ARCHIVE_EXT)

# Native build for current platform (no archive, just binary in ./dist)
native: | $(BUILD_DIR)
	@echo "==> Building native $(BUILD_DIR)/$(APP)$(EXE_EXT) (VERSION=$(VERSION) COMMIT=$(COMMIT))"
	$(call GO_BUILD_NATIVE,$(BUILD_DIR)/$(APP)$(EXE_EXT))

# --------------------------------------------------------------------
# Release archive rules
#   - On Windows: explicit rule for windows_amd64 (native build + ZIP via PowerShell)
#   - On POSIX: generic cross-compile pattern rule with tar.gz
# --------------------------------------------------------------------

ifeq ($(OS),Windows_NT)

# Only windows_amd64 is supported for release on Windows
$(BUILD_DIR)/$(APP)_$(VERSION)_windows_amd64.$(ARCHIVE_EXT): | $(BUILD_DIR)
	@echo "==> Building $(BUILD_DIR)/$(APP)_$(VERSION)_windows_amd64.exe (native Windows build, VERSION=$(VERSION) COMMIT=$(COMMIT))"
	$(call GO_BUILD_NATIVE,$(BUILD_DIR)/$(APP)_$(VERSION)_windows_amd64.exe)
	@echo "==> Creating $@ (ZIP via PowerShell Compress-Archive)"
	powershell -NoLogo -NoProfile -Command "Compress-Archive -Path '$(BUILD_DIR)/$(APP)_$(VERSION)_windows_amd64.exe','README.md','LICENCE.txt' -DestinationPath '$@' -Force"

else  # POSIX hosts: full cross-compile matrix

# Pattern rule for per-OS/ARCH archives on POSIX
# Example stem: linux_amd64  → GOOS=linux, GOARCH=amd64
$(BUILD_DIR)/$(APP)_$(VERSION)_%.$(ARCHIVE_EXT): | $(BUILD_DIR)
	@echo "==> Building $(BUILD_DIR)/$(APP)_$(VERSION)_$*$(if $(filter windows,$(call os,$*)),.exe,) (GOOS=$(call os,$*) GOARCH=$(call arch,$*) VERSION=$(VERSION) COMMIT=$(COMMIT))"
	GOOS=$(call os,$*) GOARCH=$(call arch,$*) CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" -o "$(BUILD_DIR)/$(APP)_$(VERSION)_$*$(if $(filter windows,$(call os,$*)),.exe,)" .
	@echo "==> Creating $@ (tar.gz with files at archive root)"
	tar -czf "$@" \
		-C "$(BUILD_DIR)" "$(APP)_$(VERSION)_$*$(if $(filter windows,$(call os,$*)),.exe,)" \
		-C "." README.md LICENCE.txt

endif

# --------------------------------------------------------------------
# Clean
# --------------------------------------------------------------------

clean:
	$(RM_DIST)
