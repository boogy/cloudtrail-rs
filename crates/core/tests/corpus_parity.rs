//! Buffer/stream **mode parity** on realistic CloudTrail data.
//!
//! Same oracle as `mode_parity.rs`, driven with
//! [`cloudtrail_rs_core::testing::corpus`] instead of minimal envelopes. Two
//! claims live here that the synthetic cases structurally cannot make:
//!
//! 1. **Verbatim survival.** `{"eventName":"A"}` round-trips identically
//!    whether copied or re-serialized; a record carrying `\"`, `\\`, `\t`, `😀`,
//!    `1.0`, `1.5e-7` and `9007199254740993` does not.
//!
//! 2. **Realistic resolution.** Dot-path resolution, the `eventSource` index and
//!    rule attribution against the field layouts operators write rules against,
//!    including the ones that must resolve to *nothing* (array leaf, `null`
//!    leaf, JSON-inside-a-string, absent field).
//!
//! Needs the `testing` feature.
#![cfg(feature = "testing")]

mod common;

use cloudtrail_rs_core::testing::corpus;
use common::{Verdict, assert_parity, drop_decrypt_engine, engine, gzip, no_op_engine};

/// The expected `Written` verdict for every corpus record not named in
/// `dropped`. Built from the same `&'static str` constants the input was: the
/// assertion is that the output bytes are those bytes, not that they parse
/// equal.
fn survivors_except(dropped: &[&str]) -> Verdict {
    let body = corpus::envelope_where(|r| !dropped.contains(&r.name))
        .expect("these cases always keep at least one record");
    Verdict::Written(body)
}

// ---------------------------------------------------------------------------
// Verbatim survival
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_whole_corpus_round_trips_byte_for_byte() {
    assert_parity(
        "no rules, full corpus",
        &gzip(corpus::full_envelope().as_bytes()),
        &no_op_engine(),
        Verdict::Written(corpus::full_envelope()),
    )
    .await;
}

/// Each record on its own, so a byte-level regression names the record that
/// broke instead of failing one 14-record diff.
#[tokio::test]
async fn every_record_survives_alone_byte_for_byte() {
    for record in corpus::records() {
        let body = corpus::envelope([record]);
        assert_parity(
            record.name,
            &gzip(body.as_bytes()),
            &no_op_engine(),
            Verdict::Written(body.clone()),
        )
        .await;
    }
}

/// Its bytes are deliberately not what serde would emit — `\u00fc` and `\/` are
/// decoded and re-rendered as `ü` and `/` under every serde_json feature set —
/// so a survivor that came back through a re-serializer cannot compare equal.
/// `corpus`'s `the_normalization_bait_is_still_in_place` pins that property.
#[tokio::test]
async fn the_escape_heavy_record_is_reproduced_escape_for_escape() {
    let body = corpus::envelope([corpus::find("escapes-and-unicode")]);
    assert_parity(
        "escapes and unicode, alone",
        &gzip(body.as_bytes()),
        &no_op_engine(),
        Verdict::Written(body),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Rules against realistic field layouts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_rule_drops_exactly_the_records_it_matches() {
    assert_parity(
        "drop Decrypt out of the full corpus",
        &gzip(corpus::full_envelope().as_bytes()),
        &drop_decrypt_engine(),
        survivors_except(&["kms-decrypt-from-eks"]),
    )
    .await;
}

/// A four-level dot path, the deepest the shipped example rules use.
#[tokio::test]
async fn a_four_level_dot_path_resolves() {
    let rules = engine(
        br#"
version: 1.0.0
rules:
  - name: Drop EKS Nodegroup service role
    matches:
      - field_name: userIdentity.sessionContext.sessionIssuer.userName
        regex: "^AWSServiceRoleForAmazonEKSNodegroup$"
"#,
    );
    assert_parity(
        "deep sessionIssuer path",
        &gzip(corpus::full_envelope().as_bytes()),
        &rules,
        survivors_except(&["ec2-describe-launch-template-versions"]),
    )
    .await;
}

/// The resolver has no array syntax, so `resources.ARN` resolves to `None` even
/// on the four records that have a matching ARN: such a rule drops nothing. The
/// alternative failure — matching everything with a `resources` key — would
/// silently delete four records.
#[tokio::test]
async fn a_path_through_an_array_matches_nothing() {
    let rules = engine(
        br#"
version: 1.0.0
rules:
  - name: Drop by resource ARN
    matches:
      - field_name: resources.ARN
        regex: "arn:aws:"
"#,
    );
    assert_parity(
        "array leaf is unresolvable",
        &gzip(corpus::full_envelope().as_bytes()),
        &rules,
        Verdict::Written(corpus::full_envelope()),
    )
    .await;
}

/// `additionalEventData` is a JSON *string* on the EFS record, so a path into
/// its apparent fields resolves to `None`: the resolver must not re-parse it.
#[tokio::test]
async fn a_path_into_json_inside_a_string_matches_nothing() {
    let rules = engine(
        br#"
version: 1.0.0
rules:
  - name: Drop by EFS permissions
    matches:
      - field_name: additionalEventData.Permissions
        regex: "^ReadWrite$"
"#,
    );
    assert_parity(
        "JSON-in-a-string is opaque",
        &gzip(corpus::full_envelope().as_bytes()),
        &rules,
        Verdict::Written(corpus::full_envelope()),
    )
    .await;
}

/// The counterpart, without which the test above would also pass if
/// `additionalEventData` had stopped resolving entirely.
#[tokio::test]
async fn a_path_into_a_real_object_leaf_resolves() {
    let rules = engine(
        br#"
version: 1.0.0
rules:
  - name: Drop MFA console logins
    matches:
      - field_name: additionalEventData.MFAUsed
        regex: "^Yes$"
"#,
    );
    assert_parity(
        "additionalEventData.MFAUsed",
        &gzip(corpus::full_envelope().as_bytes()),
        &rules,
        survivors_except(&["signin-console-login-mfa"]),
    )
    .await;
}

/// Three ways a field fails to resolve in one pass: `requestParameters` is an
/// object on some records, `null` on others, absent on the legacy record. A
/// resolver treating `null` or absent as a match would take most of the corpus.
#[tokio::test]
async fn null_and_absent_leaves_do_not_match() {
    let rules = engine(
        br#"
version: 1.0.0
rules:
  - name: Drop deploy role assumptions
    matches:
      - field_name: requestParameters.roleArn
        regex: "role/service-role/deploy$"
"#,
    );
    assert_parity(
        "null and absent requestParameters",
        &gzip(corpus::full_envelope().as_bytes()),
        &rules,
        survivors_except(&["sts-assume-role-service-role"]),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Index routing and rule attribution
// ---------------------------------------------------------------------------

/// A record is evaluated only against the bucket for its own `eventSource` plus
/// the un-indexable `always` bucket; with eleven sources in the corpus a routing
/// bug shows up as the wrong survivors. `assert_parity` also checks
/// `sum(RuleDrops) == RecordsDropped` — three rules, four drops, one rule each.
#[tokio::test]
async fn records_are_routed_to_the_rules_for_their_event_source() {
    let rules = engine(
        br#"
version: 1.0.0
rules:
  - name: Drop STS
    matches:
      - field_name: eventSource
        regex: "^sts\\.amazonaws\\.com$"
  - name: Drop KMS Decrypt
    matches:
      - field_name: eventSource
        regex: "^kms\\.amazonaws\\.com$"
      - field_name: eventName
        regex: "^Decrypt$"
  - name: Drop EC2 describes
    matches:
      - field_name: eventSource
        regex: "^ec2\\.amazonaws\\.com$"
      - field_name: eventName
        regex: "^Describe"
"#,
    );
    assert_parity(
        "three source-indexed rules",
        &gzip(corpus::full_envelope().as_bytes()),
        &rules,
        // The EC2 rule takes DescribeLaunchTemplateVersions but must leave
        // RunInstances — same source, different action.
        survivors_except(&[
            "sts-assume-role-service-role",
            "sts-assume-role-with-web-identity-irsa",
            "kms-decrypt-from-eks",
            "ec2-describe-launch-template-versions",
        ]),
    )
    .await;
}

/// A rule with no `eventSource` condition cannot be indexed, so it lands in the
/// `always` bucket and must be evaluated against every record. If that bucket
/// stopped being consulted, rules written this way would silently stop firing.
#[tokio::test]
async fn an_unindexable_rule_is_evaluated_against_every_source() {
    let rules = engine(
        br#"
version: 1.0.0
rules:
  - name: Drop us-east-1
    matches:
      - field_name: awsRegion
        regex: "^us-east-1$"
"#,
    );
    assert_parity(
        "always bucket spans sources",
        &gzip(corpus::full_envelope().as_bytes()),
        &rules,
        // Three different eventSources, none named by the rule.
        survivors_except(&[
            "signin-console-login-mfa",
            "iam-create-user-security-relevant",
            "minimal-legacy-record",
        ]),
    )
    .await;
}

#[tokio::test]
async fn dropping_every_record_writes_nothing() {
    let rules = engine(
        br#"
version: 1.0.0
rules:
  - name: Drop anything with an eventID
    matches:
      - field_name: eventID
        regex: "."
"#,
    );
    assert_parity(
        "every corpus record dropped",
        &gzip(corpus::full_envelope().as_bytes()),
        &rules,
        Verdict::NothingKept,
    )
    .await;
}

// ---------------------------------------------------------------------------
// At size — where the two modes actually diverge
// ---------------------------------------------------------------------------

/// Parity only matters at scale, where stream mode runs: a 400-record object is
/// several stream chunks, so a record straddling a chunk boundary is reassembled
/// here rather than in production. The fixture cycles the corpus with distinct
/// identifiers per copy — 400 identical records compress far better than real
/// CloudTrail and would exercise a size regime that does not exist.
#[tokio::test]
async fn a_large_realistic_object_round_trips_byte_for_byte() {
    let body = corpus::scale_envelope(400);
    assert_parity(
        "400 realistic records, no rules",
        &gzip(body.as_bytes()),
        &no_op_engine(),
        Verdict::Written(body.clone()),
    )
    .await;
}

#[tokio::test]
async fn a_large_realistic_object_filters_identically_in_both_modes() {
    let records = corpus::scale_records(400);
    let survivors: Vec<&String> = records
        .iter()
        .filter(|body| !body.contains(r#""eventName":"Decrypt""#))
        .collect();
    assert!(
        survivors.len() < records.len(),
        "the fixture must contain records the rule drops, or this asserts nothing"
    );
    let expected = corpus::envelope_of(&survivors);

    assert_parity(
        "400 realistic records, drop Decrypt",
        &gzip(corpus::envelope_of(&records).as_bytes()),
        &drop_decrypt_engine(),
        Verdict::Written(expected),
    )
    .await;
}
