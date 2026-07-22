//! `ConfigStore<T>`: caches a compiled config artifact behind a TTL,
//! re-validating cheaply (`ConfigSource::version`) instead of always
//! re-fetching and re-compiling the full document.
//!
//! Generic over the compiled artifact `T` and an injected `compile` fn —
//! deliberately not hardcoded to `Engine`/`RuleSet`. That keeps this task
//! decoupled from the rules engine, lets its own tests use `T = String` with
//! a call-counting compile closure and no ruleset at all, and makes
//! "compiled exactly once" directly countable, which is what a later
//! init-once test needs.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::ConfigError;
use crate::metrics::Metrics;
use crate::model::VersionTag;
use crate::ports::ConfigSource;

/// A compile step from raw document bytes to the artifact a `ConfigStore`
/// caches. Injected rather than hardcoded so this module never names
/// `RuleSet`/`Engine`.
pub type Compile<T> = Arc<dyn Fn(&[u8]) -> Result<T, ConfigError> + Send + Sync>;

struct Cached<T> {
    value: T,
    version: VersionTag,
    fetched_at: Instant,
}

struct State<T> {
    cached: Option<Cached<T>>,
}

/// Caches one compiled `T`, refreshed from `src` at most once per `ttl`.
///
/// - No cached value yet: every `get()`/`prime()` call does a full
///   fetch + compile (there is nothing cheaper to check against).
/// - Cached and within `ttl`: `get()` touches neither the source nor the
///   compile fn.
/// - Cached and past `ttl`: `version()` is checked first; a match resets the
///   TTL clock with zero re-fetch/re-compile, a mismatch triggers a real
///   fetch + compile.
/// - Any refresh failure (`version()` or `fetch()`/`compile` erroring) keeps
///   the previously cached value, if any, and counts a `ConfigLoadErrors`.
pub struct ConfigStore<T> {
    src: Arc<dyn ConfigSource>,
    ttl: Duration,
    compile: Compile<T>,
    metrics: Arc<Metrics>,
    state: Mutex<State<T>>,
}

impl<T: Clone + Send + Sync> ConfigStore<T> {
    pub fn new(
        src: Arc<dyn ConfigSource>,
        ttl: Duration,
        compile: Compile<T>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            src,
            ttl,
            compile,
            metrics,
            state: Mutex::new(State { cached: None }),
        }
    }

    /// Init-phase warm-up: an unconditional fetch + compile. Never errors,
    /// never panics — a failure here (a transient source blip at container
    /// start) increments `ConfigLoadErrors` and leaves the store empty so
    /// the first real invocation's `get()` retries it. On success, seeds the
    /// TTL clock so that first `get()` makes no further source calls.
    pub async fn prime(&self) {
        let now = Instant::now();
        match self.fetch_and_compile().await {
            Ok((value, version)) => self.store(value, version, now),
            Err(_) => self.metrics.add_config_load_errors(1),
        }
    }

    /// Returns the cached value, refreshing first if warranted. `None` only
    /// if nothing has ever been loaded successfully.
    pub async fn get(&self) -> Option<T> {
        let now = Instant::now();
        let stale = {
            let state = self.state.lock().expect("ConfigStore mutex poisoned");
            match &state.cached {
                None => true,
                Some(c) => now.duration_since(c.fetched_at) >= self.ttl,
            }
        };
        if stale {
            self.refresh(now).await;
        }
        self.state
            .lock()
            .expect("ConfigStore mutex poisoned")
            .cached
            .as_ref()
            .map(|c| c.value.clone())
    }

    async fn refresh(&self, now: Instant) {
        let cached_version = {
            let state = self.state.lock().expect("ConfigStore mutex poisoned");
            state.cached.as_ref().map(|c| c.version.clone())
        };

        let Some(cached_version) = cached_version else {
            // Never loaded: nothing cheaper to check than a real fetch.
            match self.fetch_and_compile().await {
                Ok((value, version)) => self.store(value, version, now),
                Err(_) => self.metrics.add_config_load_errors(1),
            }
            return;
        };

        match self.src.version().await {
            Err(_) => self.metrics.add_config_load_errors(1),
            Ok(new_version) if new_version == cached_version => self.touch(now),
            Ok(_) => match self.fetch_and_compile().await {
                Ok((value, version)) => self.store(value, version, now),
                Err(_) => self.metrics.add_config_load_errors(1),
            },
        }
    }

    async fn fetch_and_compile(&self) -> Result<(T, VersionTag), ConfigError> {
        let (bytes, version) = self.src.fetch().await?;
        let value = (self.compile)(&bytes)?;
        Ok((value, version))
    }

    fn store(&self, value: T, version: VersionTag, now: Instant) {
        let mut state = self.state.lock().expect("ConfigStore mutex poisoned");
        state.cached = Some(Cached {
            value,
            version,
            fetched_at: now,
        });
    }

    /// Resets the TTL clock on an unchanged revalidation, without touching
    /// the cached value.
    fn touch(&self, now: Instant) {
        let mut state = self.state.lock().expect("ConfigStore mutex poisoned");
        if let Some(c) = &mut state.cached {
            c.fetched_at = now;
        }
    }
}

// These tests instantiate `StaticConfigSource`, which is itself gated behind
// the `testing` feature (see `testing.rs`), so this module rides along.
#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use crate::testing::StaticConfigSource;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A `Compile<String>` that counts every call it makes, so tests can
    /// assert "compiled exactly N times" directly.
    fn counting_compile(calls: Arc<AtomicUsize>) -> Compile<String> {
        Arc::new(move |bytes: &[u8]| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(String::from_utf8_lossy(bytes).into_owned())
        })
    }

    #[tokio::test]
    async fn within_ttl_get_makes_zero_source_calls() {
        let src = Arc::new(StaticConfigSource::new(
            b"v1".to_vec(),
            VersionTag::Version(1),
        ));
        let metrics = Arc::new(Metrics::default());
        let compiles = Arc::new(AtomicUsize::new(0));
        let store = ConfigStore::new(
            src.clone(),
            Duration::from_secs(300),
            counting_compile(compiles.clone()),
            metrics,
        );

        assert_eq!(store.get().await, Some("v1".to_string()));
        assert_eq!(src.fetch_calls(), 1);
        assert_eq!(src.version_calls(), 0);
        assert_eq!(compiles.load(Ordering::SeqCst), 1);

        // Second call is well within the 300s TTL: no further source calls.
        assert_eq!(store.get().await, Some("v1".to_string()));
        assert_eq!(src.fetch_calls(), 1);
        assert_eq!(src.version_calls(), 0);
        assert_eq!(compiles.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn past_ttl_unchanged_costs_one_version_call_and_zero_recompiles() {
        let src = Arc::new(StaticConfigSource::new(
            b"v1".to_vec(),
            VersionTag::Version(1),
        ));
        let metrics = Arc::new(Metrics::default());
        let compiles = Arc::new(AtomicUsize::new(0));
        // Zero TTL: every get() after the first is immediately "stale".
        let store = ConfigStore::new(
            src.clone(),
            Duration::ZERO,
            counting_compile(compiles.clone()),
            metrics,
        );

        assert_eq!(store.get().await, Some("v1".to_string()));
        assert_eq!(store.get().await, Some("v1".to_string()));

        assert_eq!(
            src.fetch_calls(),
            1,
            "content never changed: one fetch total"
        );
        assert_eq!(src.version_calls(), 1, "one revalidation past TTL");
        assert_eq!(compiles.load(Ordering::SeqCst), 1, "zero re-compiles");
    }

    #[tokio::test]
    async fn past_ttl_changed_triggers_a_refetch_and_recompile() {
        let src = Arc::new(StaticConfigSource::new(
            b"v1".to_vec(),
            VersionTag::Version(1),
        ));
        let metrics = Arc::new(Metrics::default());
        let compiles = Arc::new(AtomicUsize::new(0));
        let store = ConfigStore::new(
            src.clone(),
            Duration::ZERO,
            counting_compile(compiles.clone()),
            metrics,
        );

        assert_eq!(store.get().await, Some("v1".to_string()));

        src.set(b"v2".to_vec(), VersionTag::Version(2));
        assert_eq!(store.get().await, Some("v2".to_string()));

        assert_eq!(src.fetch_calls(), 2);
        assert_eq!(src.version_calls(), 1);
        assert_eq!(compiles.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn refresh_failure_after_a_successful_load_keeps_the_cached_value() {
        let src = Arc::new(StaticConfigSource::new(
            b"v1".to_vec(),
            VersionTag::Version(1),
        ));
        let metrics = Arc::new(Metrics::default());
        let compiles = Arc::new(AtomicUsize::new(0));
        let store = ConfigStore::new(
            src.clone(),
            Duration::ZERO,
            counting_compile(compiles.clone()),
            metrics.clone(),
        );

        assert_eq!(store.get().await, Some("v1".to_string()));

        src.fail_next_version();
        let value = store.get().await;

        assert_eq!(
            value,
            Some("v1".to_string()),
            "a failed refresh must not clear or replace the cached value"
        );
        assert_eq!(
            metrics.snapshot_and_reset().config_load_errors,
            1,
            "the failed revalidation must be counted"
        );
        assert_eq!(
            compiles.load(Ordering::SeqCst),
            1,
            "no passthrough recompile"
        );
    }

    #[tokio::test]
    async fn successful_prime_seeds_the_ttl_clock() {
        let src = Arc::new(StaticConfigSource::new(
            b"v1".to_vec(),
            VersionTag::Version(1),
        ));
        let metrics = Arc::new(Metrics::default());
        let compiles = Arc::new(AtomicUsize::new(0));
        let store = ConfigStore::new(
            src.clone(),
            Duration::from_secs(300),
            counting_compile(compiles.clone()),
            metrics,
        );

        store.prime().await;
        assert_eq!(src.fetch_calls(), 1);
        assert_eq!(compiles.load(Ordering::SeqCst), 1);

        let value = store.get().await;
        assert_eq!(value, Some("v1".to_string()));
        assert_eq!(
            src.fetch_calls(),
            1,
            "prime() must have seeded the TTL clock: get() makes no further calls"
        );
        assert_eq!(src.version_calls(), 0);
        assert_eq!(compiles.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failing_prime_never_panics_and_leaves_the_store_empty_for_a_retry() {
        let src = Arc::new(StaticConfigSource::new(
            b"v1".to_vec(),
            VersionTag::Version(1),
        ));
        let metrics = Arc::new(Metrics::default());
        let compiles = Arc::new(AtomicUsize::new(0));
        let store = ConfigStore::new(
            src.clone(),
            Duration::from_secs(300),
            counting_compile(compiles.clone()),
            metrics.clone(),
        );

        src.fail_next_fetch();
        store.prime().await; // must not panic and must not return an Err

        assert_eq!(
            metrics.snapshot_and_reset().config_load_errors,
            1,
            "the failed prime() must be counted"
        );
        assert_eq!(compiles.load(Ordering::SeqCst), 0, "nothing to compile yet");

        // The store is empty, so the next get() retries from scratch.
        let value = store.get().await;
        assert_eq!(value, Some("v1".to_string()));
        assert_eq!(
            src.fetch_calls(),
            2,
            "prime's failed attempt, then get()'s retry"
        );
        assert_eq!(compiles.load(Ordering::SeqCst), 1);
    }
}
