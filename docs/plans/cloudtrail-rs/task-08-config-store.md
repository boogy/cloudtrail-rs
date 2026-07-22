# Task 08 — URI, FileConfigSource, ConfigStore, `prime()`

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 07, 09
**Do not read other task files.**

---

## Brief

**Consumes:** `ConfigSource`, `ConfigError`, `Metrics`. **Produces:** `ConfigUri`, `FileConfigSource`, `Compile<T>`, `ConfigStore<T>::{new, prime, get}` — **generic over the compiled artifact with an injected compile fn**, exactly as in SHARED.md. This task must not reference `RuleSet` or `Engine` at all; its tests instantiate `ConfigStore<String>` with a counting compile closure. That is what makes "compiled exactly once" countable in Task 16.
**Tests** with a call-counting `StaticConfigSource`: three schemes parse, unknown rejected; within TTL ⇒ zero `version()` calls; past TTL unchanged ⇒ one `version()`, zero re-compiles; past TTL changed ⇒ re-fetch + re-compile; **refresh failure after a successful load ⇒ cached ruleset retained, `ConfigLoadErrors` incremented, no passthrough**; successful `prime()` seeds the TTL clock so an immediate `get()` makes **zero** further calls; **failing `prime()` returns `()`** (no panic, no `Err`), increments `ConfigLoadErrors`, leaves the store empty so the next `get()` retries.

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
