# cloudtrail-rs — developer tasks.
# Run `make` or `make help` for the list of targets.

# ---- config ------------------------------------------------------------
CARGO        ?= cargo
LAMBDA_ARCH  ?= --arm64
COMPOSE_FILE := docker-compose.test.yml
CLI_PKG      := cloudtrail-rs
MUSL_TARGET  ?= x86_64-unknown-linux-musl
RULES_URI    := file://$(CURDIR)/examples/rules.example.yaml
SAMPLE_GZ    := crates/core/tests/fixtures/sample.json.gz

# `cargo test` only builds the ignored MiniStack tests when core carries the
# S3 decoder, and the ignored suite lives in the aws crate's dev-deps.
TEST_FLAGS   := --workspace --all-features
LINT_FLAGS   := --workspace --all-targets --all-features

.DEFAULT_GOAL := help

# ---- meta --------------------------------------------------------------
.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---- build & run -------------------------------------------------------
.PHONY: build
build: ## Debug build of the whole workspace
	$(CARGO) build --workspace

.PHONY: release
release: ## Fast local `release` profile build (lean: no LTO) — verify it builds/links
	$(CARGO) build --workspace --release

.PHONY: lambda-build
lambda-build: ## Cross-compile the four Lambda bootstrap binaries, shipped `dist` profile (needs cargo-lambda)
	$(CARGO) lambda build --profile dist $(LAMBDA_ARCH)

# ---- test & lint -------------------------------------------------------
.PHONY: test
test: ## Run the full test suite (all features)
	$(CARGO) test $(TEST_FLAGS)

.PHONY: clippy
clippy: ## Lint with clippy, warnings as errors
	$(CARGO) clippy $(LINT_FLAGS) -- -D warnings

.PHONY: fmt
fmt: ## Format all crates in place
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Verify formatting without writing
	$(CARGO) fmt --all --check

.PHONY: check
check: ## Fast type-check without producing binaries
	$(CARGO) check $(LINT_FLAGS)

.PHONY: ci
ci: fmt-check clippy tree-features test audit ## Everything CI enforces: fmt + clippy + one-decoder-per-binary + tests + audit

# ---- security & coverage ----------------------------------------------
.PHONY: audit
audit: ## Scan dependencies for RUSTSEC advisories (needs cargo-audit)
	$(CARGO) audit

.PHONY: deny
deny: ## Check licenses, bans, advisories, sources (needs cargo-deny + deny.toml)
	$(CARGO) deny check

.PHONY: coverage
coverage: ## Workspace coverage, HTML + lcov (needs cargo-llvm-cov + llvm-tools-preview)
	$(CARGO) llvm-cov $(TEST_FLAGS) --no-report
	$(CARGO) llvm-cov report --html
	$(CARGO) llvm-cov report --lcov --output-path lcov.info

# ---- version -----------------------------------------------------------
# One version for the workspace, in `[workspace.package] version`; every crate
# inherits it. The git tag is what actually ships (release.yml bakes
# $GITHUB_REF_NAME into the binaries via core/build.rs), so the only job here is
# to keep the two from drifting: `version-check` runs in release.yml's `setup`
# job and fails the whole release before a single binary is built.
.PHONY: version
version: ## Print the workspace version
	@$(CARGO) metadata --no-deps --format-version 1 | jq -r '[.packages[].version] | unique | .[]'

.PHONY: version-check
version-check: ## Fail if crates disagree on the version, or if TAG != that version (TAG defaults to the tag on HEAD)
	@set -eu; \
	vers="$$($(CARGO) metadata --no-deps --format-version 1 | jq -r '[.packages[].version] | unique | .[]')"; \
	if [ "$$(printf '%s\n' "$$vers" | wc -l | tr -d ' ')" != "1" ]; then \
		echo "FAIL: workspace crates disagree on version:"; printf '  %s\n' $$vers; \
		echo "  every crates/*/Cargo.toml must use 'version.workspace = true'"; exit 1; \
	fi; \
	tag="$${TAG:-$$(git describe --tags --exact-match 2>/dev/null || true)}"; \
	if [ -z "$$tag" ]; then echo "ok: workspace version $$vers (no tag on HEAD to compare)"; exit 0; fi; \
	if [ "$${tag#v}" != "$$vers" ]; then \
		echo "FAIL: tag $$tag != workspace version $$vers"; \
		echo "  run 'make bump VERSION=$${tag#v}', commit, then re-tag"; exit 1; \
	fi; \
	echo "ok: tag $$tag == workspace version $$vers"

.PHONY: bump
bump: ## Set the workspace version and refresh Cargo.lock (make bump VERSION=1.2.3)
	@set -eu; \
	test -n "$(VERSION)" || { echo "usage: make bump VERSION=1.2.3"; exit 1; }; \
	printf '%s' '$(VERSION)' | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' \
		|| { echo "VERSION must be semver (1.2.3 or 1.2.3-rc.1), got '$(VERSION)'"; exit 1; }; \
	awk -v v='$(VERSION)' ' \
		/^\[/ { f = ($$0 == "[workspace.package]") } \
		f && !done && /^version[[:space:]]*=/ { print "version = \"" v "\""; done = 1; next } \
		{ print } \
		END { if (!done) { print "no version line in [workspace.package]" > "/dev/stderr"; exit 1 } } \
	' Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml
	@$(CARGO) update --workspace --quiet
	@$(MAKE) --no-print-directory version-check TAG=v$(VERSION)
	@echo "next: git commit -am 'release: v$(VERSION)' && git push -u origin HEAD"
	@echo "      open a PR, get it merged, then: git checkout main && git pull && make tag"

# Tagging happens on merged main, never on a branch. GitHub builds a release's
# "What's Changed" from the pull requests merged inside the tag's commit range;
# a tag sitting on an un-merged branch head has zero merged PRs in that range,
# so the release ships with an empty changelog (this is what happened to v0.2.0,
# tagged on fix/aws-config-ring-http-client before the squash-merge). Everything
# below is that invariant made enforceable.
#
# The tag is signed (`git tag -s`), not lightweight: the repo's `tags` ruleset
# has required_signatures active, and a bare `git tag` creates a ref with no tag
# object and therefore nothing to sign. `-m` is mandatory too — signing forces an
# annotated tag, and without a message `git tag` either opens an editor or dies
# with "fatal: no tag message?" in any non-interactive run.
.PHONY: tag
tag: ## Tag merged main with the workspace version (refuses to tag anywhere else)
	@set -eu; \
	vers="$$($(CARGO) metadata --no-deps --format-version 1 | jq -r '[.packages[].version] | unique | .[]' | head -1)"; \
	branch="$$(git rev-parse --abbrev-ref HEAD)"; \
	if [ "$$branch" != "main" ]; then \
		echo "FAIL: on '$$branch' — release tags must sit on main, or the release"; \
		echo "  notes come out empty. Merge the release PR, then:"; \
		echo "    git checkout main && git pull && make tag"; exit 1; \
	fi; \
	if ! git diff --quiet || ! git diff --cached --quiet; then \
		echo "FAIL: working tree is dirty — commit or stash before tagging"; exit 1; \
	fi; \
	git fetch --quiet origin main; \
	if [ "$$(git rev-parse HEAD)" != "$$(git rev-parse origin/main)" ]; then \
		echo "FAIL: local main is not origin/main — run 'git pull' first"; exit 1; \
	fi; \
	if [ -z "$$(git config --get user.signingkey)" ]; then \
		echo "FAIL: no user.signingkey configured — release tags must be signed"; \
		echo "  the repo's 'tags' ruleset rejects an unsigned tag"; exit 1; \
	fi; \
	$(MAKE) --no-print-directory version-check TAG="v$$vers"; \
	git tag -s "v$$vers" -m "release v$$vers"; \
	echo "tagged v$$vers at $$(git rev-parse --short HEAD) on main"; \
	echo "next: git push origin v$$vers"

# ---- release ----------------------------------------------------------
# The release pipeline lives entirely in .github/workflows/release.yml: native
# per-arch static-musl builds (no zig/goreleaser), archives + checksums, the
# GitHub Release, multi-arch Lambda images, and cosign signatures. It runs
# `make version-check` first — a tag that disagrees with [workspace.package]
# version never builds.
.PHONY: release-musl
release-musl: ## Local static-musl shipped `dist` build of the whole workspace for one target (needs musl-tools + rustup target)
	CC_x86_64_unknown_linux_musl=musl-gcc CC_aarch64_unknown_linux_musl=musl-gcc \
		$(CARGO) build --workspace --profile dist --target $(MUSL_TARGET)

# ---- toolchain ---------------------------------------------------------
.PHONY: install-tools
install-tools: ## Install every dev/release tool + rustup targets and components
	$(CARGO) install cargo-lambda cargo-audit cargo-deny cargo-llvm-cov cargo-edit cargo-outdated
	rustup component add llvm-tools-preview
	rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl

# ---- CLI convenience ---------------------------------------------------
.PHONY: validate
validate: ## Validate the example ruleset (prints always-bucket warnings)
	$(CARGO) run -p $(CLI_PKG) -- validate $(RULES_URI)

.PHONY: sample
sample: ## Show KEEP/DROP breakdown for the sample fixture
	$(CARGO) run -p $(CLI_PKG) -- test examples/rules.example.yaml $(SAMPLE_GZ)

# ---- MiniStack integration --------------------------------------------
.PHONY: ministack-up
ministack-up: ## Start the local S3/SSM stack on :4566
	docker compose -f $(COMPOSE_FILE) up -d

.PHONY: ministack-down
ministack-down: ## Stop and remove the local stack
	docker compose -f $(COMPOSE_FILE) down

.PHONY: ministack-test
ministack-test: ## Run the #[ignore]d MiniStack tests (requires ministack-up first)
	$(CARGO) test --workspace -- --ignored

# ---- dependency maintenance -------------------------------------------
.PHONY: update
update: ## Update Cargo.lock within existing semver ranges
	$(CARGO) update

.PHONY: upgrade
upgrade: ## Bump Cargo.toml deps to latest (needs cargo-edit: `cargo install cargo-edit`)
	$(CARGO) upgrade
	$(CARGO) update

.PHONY: outdated
outdated: ## List outdated dependencies (needs `cargo install cargo-outdated`)
	$(CARGO) outdated --workspace

# ---- housekeeping ------------------------------------------------------
.PHONY: clean
clean: ## Remove the target/ build directory
	$(CARGO) clean

.PHONY: tree-features
tree-features: ## Prove each lambda binary pulls in exactly one decode-* feature
	@set -eu; \
	fail=0; \
	for m in s3 sns sqs eventbridge; do \
		tree="$$($(CARGO) tree -p cloudtrail-rs-lambda-$$m -e features)"; \
		for other in s3 sns sqs eventbridge; do \
			if [ "$$m" != "$$other" ]; then \
				n="$$(printf '%s\n' "$$tree" | grep -c "decode-$$other" || true)"; \
				if [ "$$n" != "0" ]; then \
					echo "FAIL: lambda-$$m pulls in decode-$$other ($$n occurrence(s))"; \
					fail=1; \
				fi; \
			fi; \
		done; \
	done; \
	if [ "$$fail" != "0" ]; then exit 1; fi; \
	echo "ok: each lambda pulls in exactly one decoder"

.PHONY: core-no-aws
core-no-aws: ## Prove crates/core has zero AWS dependencies (hexagonal boundary)
	@set -eu; \
	tree="$$($(CARGO) tree -p cloudtrail-rs-core -e normal --all-features)"; \
	hits="$$(printf '%s\n' "$$tree" | grep -iE '(^|[^a-z])aws[-_]|smithy' || true)"; \
	if [ -n "$$hits" ]; then \
		echo "FAIL: cloudtrail-rs-core depends on AWS crates — the hexagonal"; \
		echo "boundary (root CLAUDE.md invariant 1) says core reaches AWS only"; \
		echo "through the ports in crates/core/src/ports.rs. Move this to crates/aws."; \
		printf '%s\n' "$$hits"; \
		exit 1; \
	fi; \
	echo "ok: cloudtrail-rs-core has zero AWS dependencies"
