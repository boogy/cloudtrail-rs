# Task 04 — Field path resolution

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 02
**Do not read other task files.**

---

## Brief

**Produces:** `pub fn resolve<'a>(v: &'a Value, path: &str) -> Option<Cow<'a, str>>`.
Dot-path traversal + scalar coercion. **Table-driven test:** string borrowed (assert `Cow::Borrowed`); nested `userIdentity.sessionContext.sessionIssuer.arn`; `readOnly: true` → `"true"`; number → literal; missing → `None`; `null` → `None`; object leaf → `None`; array leaf → `None`; path through a non-object → `None`; **`resources[0].ARN` → `None`** (documented v1 limitation, not a crash).

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
