//! The agreement property: every evaluator must return the identical
//! `Decision` for every record. `evaluate_linear` is the oracle -- it has no
//! index and no projection, so it cannot be wrong in the ways the optimised
//! paths can. Over-exclusion by the index is silent data loss, which is why
//! this property is enforced rather than assumed.
//!
//! Needs the `testing` feature; `make test` / `make ci` run `--all-features`.
#![cfg(feature = "testing")]

use cloudtrail_rs_core::config::rules::RuleSet;
use cloudtrail_rs_core::filter::{Decision, Engine};
use cloudtrail_rs_core::testing::corpus;
use serde_json::{Value, json};

const EXAMPLE_RULES: &[u8] = include_bytes!("fixtures/rules.example.yaml");

fn engine() -> Engine {
    Engine::new(RuleSet::parse(EXAMPLE_RULES).expect("example ruleset must parse"))
        .expect("engine must build")
}

/// Built once and shared across every generated case in
/// `raw_agrees_with_linear_on_generated_records`: constructing an `Engine` per
/// case (256 by default) is a repeat compile of the same 25-rule ruleset and
/// dominates that test's runtime for no property-strengthening reason.
fn cached_engine() -> &'static Engine {
    static ENGINE: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();
    ENGINE.get_or_init(engine)
}

#[test]
fn indexed_agrees_with_linear_on_corpus() {
    let engine = engine();
    let mut checked = 0usize;
    for record in corpus::records() {
        let value: Value =
            serde_json::from_str(record.json).expect("corpus record must be valid JSON");
        assert_eq!(
            engine.evaluate_linear(&value),
            engine.evaluate(&value),
            "indexed evaluator disagreed with the oracle on corpus record {:?}",
            record.name
        );
        checked += 1;
    }
    assert!(checked > 0, "corpus was empty: the property proved nothing");
}

/// The example ruleset is committed in two places and they must not drift:
/// `examples/` is what users copy, `tests/fixtures/` is what the suite
/// compiles against. Nothing enforced this before -- a fix applied to one
/// copy would silently leave the other wrong.
#[test]
fn example_ruleset_copies_are_identical() {
    let shipped = include_str!("../../../examples/rules.example.yaml");
    let fixture = include_str!("fixtures/rules.example.yaml");
    assert_eq!(
        shipped, fixture,
        "examples/rules.example.yaml and crates/core/tests/fixtures/rules.example.yaml \
         have drifted; they must be byte-identical"
    );
}

/// `examples/rules.v2.example.yaml` is the documentation users copy from, so a
/// silent break there is a broken doc. Compiling it here makes it a live test
/// input: it must parse, build an engine, and agree three ways over the whole
/// corpus.
///
/// Note which path this actually covers: the file demonstrates `[*]`, so
/// `has_wildcard()` holds and `evaluate_raw` takes the full-parse fallback
/// rather than the projected parse. That makes this the widest coverage of the
/// *fallback* branch in the suite -- 16 rules over every operator -- while the
/// projected branch is covered by the wildcard-free shipped ruleset.
#[test]
fn v2_reference_example_compiles_and_agrees_three_ways() {
    let text = include_str!("../../../examples/rules.v2.example.yaml");
    let engine =
        Engine::new(RuleSet::parse(text.as_bytes()).expect("v2 reference example must parse"))
            .expect("v2 reference example must build an engine");

    let mut checked = 0usize;
    for record in corpus::records() {
        let value: Value =
            serde_json::from_str(record.json).expect("corpus record must be valid JSON");
        let linear = engine.evaluate_linear(&value);
        assert_eq!(
            linear,
            engine.evaluate(&value),
            "indexed evaluator disagreed with the oracle on {:?}",
            record.name
        );
        assert_eq!(
            linear,
            engine
                .evaluate_raw(record.json)
                .expect("corpus record must parse via the projected path"),
            "projected evaluator disagreed with the oracle on {:?}",
            record.name
        );
        checked += 1;
    }
    assert!(checked > 0, "corpus was empty: the property proved nothing");
}

/// The reference example earns its name only if it actually exercises every v2
/// option. Without this, an operator could be dropped from the file and the
/// docs would quietly stop demonstrating it.
#[test]
fn v2_reference_example_uses_every_option() {
    let text = include_str!("../../../examples/rules.v2.example.yaml");
    for needle in [
        "version: 2.",  // v2 schema
        "meta:",        // optional metadata block
        "equals:",      // operator 1
        "any_of:",      // operator 2
        "regex:",       // operator 3
        "absent: true", // operator 4, both polarities
        "absent: false",
        "negate: true", // condition-level negation
        "[0].",         // fixed array subscript
        "[*].",         // wildcard array subscript
    ] {
        assert!(
            text.contains(needle),
            "v2 reference example no longer demonstrates {needle:?}"
        );
    }

    // Nested traversal deeper than one level -- the `a.b.c` path form.
    assert!(
        text.contains("userIdentity.sessionContext.sessionIssuer."),
        "v2 reference example no longer demonstrates a deep nested path"
    );
}

#[test]
fn example_ruleset_is_v2_and_uses_absent() {
    let shipped = include_str!("fixtures/rules.example.yaml");
    assert!(
        shipped.contains("version: 2."),
        "example ruleset must be migrated to schema v2"
    );
    assert!(
        shipped.contains("absent:"),
        "example ruleset must express the errorCode-absent condition (spec F1)"
    );
    RuleSet::parse(shipped.as_bytes()).expect("shipped example must parse");
}

/// Guards spec finding F1 against a revert: with the old `errorCode` regex
/// this pair collapses to Keep/Drop the wrong way round.
#[test]
fn shipped_describe_rule_keeps_denied_and_drops_successful() {
    let engine = engine();

    let successful = json!({
        "eventName": "DescribeInstances",
        "readOnly": true,
        "userAgent": "aws-cli/2.15.0",
    });
    let denied = json!({
        "eventName": "DescribeInstances",
        "readOnly": true,
        "userAgent": "aws-cli/2.15.0",
        "errorCode": "AccessDenied",
    });

    assert!(
        matches!(engine.evaluate(&successful), Decision::Drop { .. }),
        "a successful automated Describe is noise and must be dropped"
    );
    assert_eq!(
        engine.evaluate(&denied),
        Decision::Keep,
        "an AccessDenied automated Describe is a security signal and must be kept"
    );
}

/// The three-way agreement property. `evaluate_linear` has no index and no
/// projection, so it is the oracle; the other two must match it on every
/// record. A divergence is silent data loss.
#[test]
fn raw_agrees_with_linear_and_indexed_on_corpus() {
    let engine = engine();
    let mut checked = 0usize;
    for record in corpus::records() {
        let value: Value =
            serde_json::from_str(record.json).expect("corpus record must be valid JSON");
        let linear = engine.evaluate_linear(&value);
        let indexed = engine.evaluate(&value);
        let raw = engine
            .evaluate_raw(record.json)
            .expect("a corpus record parses, so projection must not error");
        assert_eq!(linear, indexed, "indexed diverged on {:?}", record.name);
        assert_eq!(linear, raw, "raw diverged on {:?}", record.name);
        checked += 1;
    }
    assert!(checked > 0, "corpus was empty: the property proved nothing");
}

/// The shape `testing::corpus` never constructs: an `eventSource`-unconstrained
/// rule ("IAM Session Renewals") firing under the `sts.amazonaws.com` bucket
/// key that "Service Role STS Operations" also owns.
#[test]
fn indexed_agrees_with_linear_when_an_any_event_source_rule_shares_anothers_bucket() {
    let engine = engine();
    let record = json!({
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "requestParameters": {"roleSessionName": "botocore-session-12345"},
        "userIdentity": {"type": "AssumedRole"}
    });
    let text = record.to_string();
    let linear = engine.evaluate_linear(&record);
    let indexed = engine.evaluate(&record);
    let raw = engine.evaluate_raw(&text).expect("record parses");
    assert!(
        matches!(linear, Decision::Drop { .. }),
        "record must exercise the unconstrained rule, or this test proves nothing"
    );
    assert_eq!(
        linear, indexed,
        "indexed diverged from the oracle on the shared-bucket record"
    );
    assert_eq!(
        linear, raw,
        "raw diverged from the oracle on the shared-bucket record"
    );
}

/// Projection must error exactly when a full parse errors, so the pipeline's
/// "unparseable record is KEPT" rule is unchanged.
#[test]
fn raw_errors_exactly_when_full_parse_errors() {
    let engine = engine();
    for bad in [
        r#"{"eventName":"A","x":{"a":[1,2,3,]}}"#,
        r#"{"eventName":"A","x":{a:1}}"#,
        r#"{"eventName":"A""#,
        r#"not json at all"#,
        r#""#,
        // T13: a lone (unpaired) UTF-16 surrogate escape in a subtree no
        // rule references. `serde::de::IgnoredAny` skips a value's bytes
        // structurally without decoding string escapes, so it used to
        // accept this where a full `Value` parse rejects it -- silently
        // turning an unparseable record into one the engine evaluated (and
        // could drop) instead of keeping.
        r#"{"eventName":"A","x":"\uD800"}"#,
    ] {
        let full_ok = serde_json::from_str::<Value>(bad).is_ok();
        let raw_ok = engine.evaluate_raw(bad).is_ok();
        assert_eq!(full_ok, raw_ok, "disagreed on {bad:?}");
    }
}

/// The wildcard fallback is load-bearing, not an optimization: with no `[*]`
/// path in the ruleset, `has_wildcard()` is always false and this branch never
/// runs. The shipped example ruleset has no such path, so the corpus and
/// proptest properties above never exercise it.
///
/// This ruleset has only a `[*]` path -- no fixed subscript sharing its array
/// node -- so projection's wildcard capture is plain first-scalar-wins
/// (`project.rs`'s `projects_wildcard_as_first_scalar`). The matching element
/// here is the *second* one, which first-scalar-wins misses but
/// `evaluate_linear`'s existential `visit_values` does not.
#[test]
fn evaluate_raw_wildcard_fallback_handles_a_non_first_match() {
    let yaml = br#"
version: 2.0.0
rules:
  - name: Noisy bucket anywhere
    matches:
      - field: "resources[*].ARN"
        equals: "arn:aws:s3:::noisy-bucket"
"#;
    let engine = Engine::new(RuleSet::parse(yaml).expect("must parse")).expect("engine must build");
    let record = json!({
        "resources": [
            {"ARN": "arn:aws:s3:::quiet-bucket"},
            {"ARN": "arn:aws:s3:::noisy-bucket"}
        ]
    });
    assert_eq!(
        engine.evaluate_linear(&record),
        engine
            .evaluate_raw(&record.to_string())
            .expect("record parses"),
        "raw diverged from linear when the matching element was not first"
    );
}

/// A fixed subscript and a wildcard addressing the same array node: per
/// project.rs's `wildcard_sharing_a_node_with_a_fixed_index_skips_that_element`,
/// `visit_seq` gives the indexed child priority at that position, so the
/// wildcard child in `project()` never sees element 0 -- while
/// `evaluate_linear`'s existential wildcard checks element 0 first (and
/// short-circuits there, since it matches). Without the fallback, `evaluate_raw`
/// would see only element 1 through the wildcard slot and disagree with
/// `evaluate_linear`.
#[test]
fn evaluate_raw_wildcard_fallback_handles_index_and_wildcard_sharing_a_node() {
    let yaml = br#"
version: 2.0.0
rules:
  - name: Wildcard matches the shared element
    matches:
      - field: "resources[*].ARN"
        equals: "arn:aws:s3:::a"
  - name: Also touches the fixed subscript
    matches:
      - field: "resources[0].ARN"
        equals: "arn:aws:s3:::never-matches-this-value"
"#;
    let engine = Engine::new(RuleSet::parse(yaml).expect("must parse")).expect("engine must build");
    let record = json!({
        "resources": [
            {"ARN": "arn:aws:s3:::a"},
            {"ARN": "arn:aws:s3:::other"}
        ]
    });
    assert_eq!(
        engine.evaluate_linear(&record),
        engine
            .evaluate_raw(&record.to_string())
            .expect("record parses"),
        "raw diverged from linear when a fixed index and a wildcard shared an array node"
    );
}

/// The example ruleset (80 `regex:` + 1 `absent: true`) and the two wildcard
/// fallback tests above never exercise `Op::Equals`, `Op::AnyOf`,
/// `Op::Absent(false)`, or `negate` through `match_fires_projected` -- the
/// example has none of them, and the wildcard tests take the full-parse
/// early return before `match_fires_projected` ever runs. This ruleset
/// deliberately has no `[*]` segment anywhere, so `Projection::has_wildcard`
/// is false by construction and `evaluate_raw` cannot take that early
/// return; there is no record that would separate "fell back" from "went
/// through projection" to assert against, so this doc comment is the pin.
///
/// Covers, each via a rule reachable only by dodging the earlier ones:
/// `equals`, `any_of`, `negate` on both `equals` and `any_of`, `absent: true`,
/// `absent: false`, a nested path (`userIdentity.type`), a fixed array
/// subscript (`resources[0].ARN`), a bool leaf, an integer leaf, and two
/// float-lexed leaves whose JSON text disagrees with `f64::to_string()`
/// (`1.0`, `1.5e-7` -- T11's bug). Missing-entirely, `null`, object, and
/// array leaves are exercised against `equals`/`any_of`/`absent` alike,
/// since `path.rs` yields nothing for all four and a coercion bug would
/// treat one of them as an empty-string match instead.
#[test]
fn evaluate_raw_agrees_with_linear_across_operators_and_value_shapes() {
    let yaml = br#"
version: 2.0.0
rules:
  - name: Equals eventName is Decrypt
    matches:
      - field: eventName
        equals: "Decrypt"
  - name: AnyOf eventSource kms or s3
    matches:
      - field: eventSource
        any_of: ["kms.amazonaws.com", "s3.amazonaws.com"]
  - name: Negated equals eventName is not ConsoleLogin
    matches:
      - field: eventName
        equals: "ConsoleLogin"
        negate: true
  - name: Negated any_of userIdentity type is not privileged
    matches:
      - field: userIdentity.type
        any_of: ["Root", "IAMUser"]
        negate: true
  - name: Resources first ARN is the critical bucket
    matches:
      - field: "resources[0].ARN"
        equals: "arn:aws:s3:::critical-bucket"
  - name: Response count equals one
    matches:
      - field: responseElements.count
        equals: "1"
  - name: ReadOnly is true
    matches:
      - field: readOnly
        equals: "true"
  - name: Latency equals a scientific-notation literal
    matches:
      - field: latency
        equals: "1.5e-7"
  - name: Ratio equals a trailing-zero float literal
    matches:
      - field: ratio
        equals: "1.0"
  - name: ErrorCode absent
    matches:
      - field: errorCode
        absent: true
  - name: ErrorCode present
    matches:
      - field: errorCode
        absent: false
"#;
    let rule_set = RuleSet::parse(yaml).expect("inline ruleset must parse");
    let rule_count = rule_set.rules.len();
    let engine = Engine::new(rule_set).expect("inline ruleset must compile");

    // Every record below shares this prefix unless noted: it dodges rules
    // 0-3 (eventName != "Decrypt", eventName == "ConsoleLogin" so the
    // negated equals doesn't fire, eventSource not in the any_of set,
    // userIdentity.type == "IAMUser" so the negated any_of doesn't fire) so
    // later cases can isolate rules 4-10 without an earlier broad rule
    // shadowing them.
    let neutral = || {
        json!({
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "userIdentity": {"type": "IAMUser"}
        })
    };
    fn with(mut base: Value, extra: Value) -> Value {
        base.as_object_mut()
            .expect("neutral base is an object")
            .extend(extra.as_object().expect("extra is an object").clone());
        base
    }

    let records: Vec<(&str, Value)> = vec![
        ("baseline: errorCode absent entirely", neutral()),
        (
            "equals fires: eventName literally Decrypt",
            json!({"eventName": "Decrypt", "eventSource": "other.amazonaws.com"}),
        ),
        (
            "any_of fires: eventSource is kms.amazonaws.com",
            json!({"eventName": "SomethingElse", "eventSource": "kms.amazonaws.com"}),
        ),
        (
            "negated equals fires: eventName missing entirely",
            json!({
                "eventSource": "signin.amazonaws.com",
                "userIdentity": {"type": "IAMUser"}
            }),
        ),
        (
            "negated equals fires: eventName is an object, not a scalar",
            json!({
                "eventName": {"nested": "x"},
                "eventSource": "signin.amazonaws.com",
                "userIdentity": {"type": "IAMUser"}
            }),
        ),
        (
            "negated equals fires: eventName is an array, not a scalar",
            json!({
                "eventName": ["a", "b"],
                "eventSource": "signin.amazonaws.com",
                "userIdentity": {"type": "IAMUser"}
            }),
        ),
        (
            "negated equals fires: eventName is null",
            json!({
                "eventName": null,
                "eventSource": "signin.amazonaws.com",
                "userIdentity": {"type": "IAMUser"}
            }),
        ),
        (
            "negated any_of fires: userIdentity.type is a non-member value",
            json!({
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "userIdentity": {"type": "AssumedRole"}
            }),
        ),
        (
            "negated any_of fires: userIdentity missing entirely",
            json!({"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com"}),
        ),
        (
            "negated any_of fires: userIdentity.type is null",
            json!({
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "userIdentity": {"type": null}
            }),
        ),
        (
            "negated any_of fires: userIdentity is a scalar, not an object",
            json!({
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "userIdentity": "AROAEXAMPLE"
            }),
        ),
        (
            "negated any_of does not fire: userIdentity.type is Root",
            with(neutral(), json!({"userIdentity": {"type": "Root"}})),
        ),
        (
            "fixed subscript equals fires: resources[0].ARN matches",
            with(
                neutral(),
                json!({"resources": [{"ARN": "arn:aws:s3:::critical-bucket"}]}),
            ),
        ),
        (
            "fixed subscript does not fire: resources is empty",
            with(neutral(), json!({"resources": []})),
        ),
        (
            "fixed subscript does not fire: element 0 has no ARN key",
            with(
                neutral(),
                json!({"resources": [{"type": "AWS::S3::Bucket"}]}),
            ),
        ),
        (
            "fixed subscript does not fire: resources is an object, not an array",
            with(
                neutral(),
                json!({"resources": {"ARN": "arn:aws:s3:::critical-bucket"}}),
            ),
        ),
        (
            "integer leaf equals fires: responseElements.count is 1",
            with(neutral(), json!({"responseElements": {"count": 1}})),
        ),
        (
            "integer leaf equals does not fire: responseElements.count is 2",
            with(neutral(), json!({"responseElements": {"count": 2}})),
        ),
        (
            "bool leaf equals fires: readOnly is true",
            with(neutral(), json!({"readOnly": true})),
        ),
        (
            "bool leaf equals does not fire: readOnly is false",
            with(neutral(), json!({"readOnly": false})),
        ),
        (
            "float leaf equals fires: latency is 1.5e-7 (T11's bug)",
            with(neutral(), json!({"latency": 1.5e-7})),
        ),
        (
            "float leaf equals fires: ratio is 1.0 (T11's bug)",
            with(neutral(), json!({"ratio": 1.0})),
        ),
        (
            "absent(false) fires: errorCode is present",
            with(neutral(), json!({"errorCode": "AccessDenied"})),
        ),
        (
            "absent(true) still fires: errorCode is null",
            with(neutral(), json!({"errorCode": null})),
        ),
        (
            "absent(true) still fires: errorCode is an empty object",
            with(neutral(), json!({"errorCode": {}})),
        ),
        (
            "absent(true) still fires: errorCode is an empty array",
            with(neutral(), json!({"errorCode": []})),
        ),
        (
            "absent(true) still fires: errorCode is a non-empty array",
            with(neutral(), json!({"errorCode": ["x"]})),
        ),
    ];

    let mut fired_rules = std::collections::HashSet::new();
    for (label, record) in &records {
        let text = record.to_string();
        let linear = engine.evaluate_linear(record);
        let indexed = engine.evaluate(record);
        let raw = engine
            .evaluate_raw(&text)
            .unwrap_or_else(|e| panic!("{label}: record must parse: {e}; record={record}"));
        assert_eq!(
            linear, indexed,
            "{label}: indexed diverged from the oracle; record={record}"
        );
        assert_eq!(
            linear, raw,
            "{label}: raw diverged from the oracle; record={record}"
        );
        if let Decision::Drop { rule_idx } = linear {
            fired_rules.insert(rule_idx);
        }
    }
    assert_eq!(
        fired_rules.len(),
        rule_count,
        "every rule must fire on at least one record, or this test is vacuously \
         comparing Keep to Keep for that rule; fired {fired_rules:?} of {rule_count} rules"
    );
}

proptest::proptest! {
    /// Generated records, including missing fields and non-scalar leaves, must
    /// not separate the three evaluators.
    #[test]
    fn raw_agrees_with_linear_on_generated_records(
        event_source in proptest::option::of("[a-z]{1,8}\\.amazonaws\\.com"),
        event_name in proptest::option::of("[A-Za-z]{1,12}"),
        read_only in proptest::option::of(proptest::bool::ANY),
        error_code in proptest::option::of("[A-Za-z]{1,16}"),
    ) {
        let mut obj = serde_json::Map::new();
        if let Some(v) = event_source { obj.insert("eventSource".into(), v.into()); }
        if let Some(v) = event_name { obj.insert("eventName".into(), v.into()); }
        if let Some(v) = read_only { obj.insert("readOnly".into(), v.into()); }
        if let Some(v) = error_code { obj.insert("errorCode".into(), v.into()); }
        let value = Value::Object(obj);
        let text = value.to_string();

        let engine = cached_engine();
        proptest::prop_assert_eq!(
            engine.evaluate_linear(&value),
            engine.evaluate_raw(&text).expect("generated JSON parses")
        );
    }
}
