# Task 03 — Rules: parse and validate

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 02
**Do not read other task files.**

---

## Brief

**Consumes:** `ConfigError`. **Produces:** `RuleSet`, `Rule`, `Match`, `RuleSet::parse(&[u8]) -> Result<RuleSet, ConfigError>`. **This task does not compile regexes** — that is `Engine::new` in Task 05/06. It parses and structurally validates only; regex *compilability* is checked here by a throwaway compile in the validator, but no compiled artifact is produced or stored.
Commit the user's 24-rule example verbatim to **both** `crates/core/tests/fixtures/rules.example.yaml` **and** `examples/rules.example.yaml` — Task 17's CLI tests reference the `examples/` path and run before the docs task. `deny_unknown_fields` on `RuleSet`/`Rule`/`Match`; `meta` free-form.
**Tests:** parses to 24 rules with expected `matches` counts; **`created_at: 2024-01-01` does not break parsing**; rejects `field_names:` typo, `regexp:` typo, `version: 2.0.0`, uncompilable regex, oversized regex (`size_limit`), duplicate `name`, empty `matches`, empty `name`; accepts `rules: []`.

---

## How to work this task

- **TDD, strictly.** Write the failing test first, run it and watch it fail for the
  right reason, implement the minimum that makes it pass, run it green, commit.
- **Stay in scope.** Do not read other task files. Do not refactor code belonging to
  other tasks. If this brief cannot be implemented as written, stop and report to the
  orchestrator rather than expanding scope or inventing an interface.
- **Green before you commit:** `cargo test --workspace --all-features` and
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- **Commit message subject must start `task-NN: `.** No co-author or "generated with"
  trailers. One task, one logical commit.
- **Never undo your own edits with git** (`checkout`/`restore`/`stash`/`reset --hard`) —
  it destroys uncommitted work. Reverse the edit the same way you made it.

## Report back

Files changed, test names added, commit sha, and **any interface deviation** from
`SHARED.md`.
