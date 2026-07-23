# cloudtrail-rs — developer tasks.
# Run `make` or `make help` for the list of targets.

# ---- config ------------------------------------------------------------
CARGO        ?= cargo
LAMBDA_ARCH  ?= --arm64
COMPOSE_FILE := docker-compose.test.yml
CLI_PKG      := cloudtrail-rs
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
release: ## Optimized release build (fat LTO, stripped) of every crate
	$(CARGO) build --workspace --release

.PHONY: lambda-build
lambda-build: ## Cross-compile the four Lambda bootstrap binaries (needs cargo-lambda + zig)
	$(CARGO) lambda build --release $(LAMBDA_ARCH)

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
ci: fmt-check clippy test ## Everything CI enforces: fmt + clippy + tests

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
tree-features: ## Prove lambda-s3 pulls in no other decoder feature (expect 0)
	$(CARGO) tree -p cloudtrail-rs-lambda-s3 -e features | grep -c decode-sqs
