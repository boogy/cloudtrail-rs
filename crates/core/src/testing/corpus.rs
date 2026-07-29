//! A realistic CloudTrail corpus: records shaped the way AWS actually emits
//! them, kept as **verbatim source text** rather than `serde_json::json!`
//! values.
//!
//! # Why raw text, not `json!`
//!
//! Both processing modes copy a surviving record with `RawValue::get()` — the
//! *original bytes*, never re-serialized — and assemble the output as
//! `{"Records":[` + survivors joined by `,` + `]}`. A corpus built from
//! `json!` + `to_string()` would be pre-normalized by serde and could not
//! detect a regression that re-serializes instead of copying: escapes would be
//! re-escaped identically, numbers re-rendered identically, key order
//! preserved by luck. Storing the exact bytes and rebuilding the expected
//! output from those same bytes makes the verbatim-copy claim falsifiable.
//!
//! That is also why the records below are compact single-line JSON with
//! deliberate irregularities (mixed key order, `1.0` and exponent numbers,
//! `\u` escapes, literal non-ASCII, embedded JSON-in-a-string): each one is a
//! normalization a re-serializing implementation would silently "fix".
//!
//! # Why synthetic, and how to keep it that way
//!
//! Real CloudTrail carries account IDs, role and user names, source IPs, and
//! occasionally sensitive `requestParameters` — none of which belongs in a
//! public repository. Every identifier here is from a documentation-reserved
//! range: accounts [`ALLOWED_ACCOUNT_IDS`], addresses from TEST-NET-1
//! (`192.0.2.0/24`) and TEST-NET-2 (`198.51.100.0/24`), and `EXAMPLE`-suffixed
//! principal IDs. [`unexpected_account_ids`] enforces it, so a real log pasted
//! in later fails a test instead of shipping.

/// One corpus record: the verbatim JSON text plus the metadata a test needs to
/// predict what the engine will do with it.
#[derive(Debug, Clone, Copy)]
pub struct CorpusRecord {
    /// Stable handle for `assert_parity` case names and [`find`].
    pub name: &'static str,
    pub event_source: &'static str,
    pub event_name: &'static str,
    /// The record exactly as it would appear inside a real `Records` array.
    /// Compact, single-line, byte-for-byte what the output must reproduce.
    pub json: &'static str,
    /// The `eventID` value as it literally appears in `json`. Used by
    /// [`scale_envelope`] to mint distinct copies, and asserted to be present.
    pub event_id: &'static str,
    /// The `requestID` value as it literally appears in `json`, same purpose.
    pub request_id: &'static str,
    /// What this record exists to exercise. Read this before deleting one.
    pub notes: &'static str,
}

/// Account IDs permitted to appear anywhere in the corpus. `123456789012` and
/// `210987654321` are AWS's documentation examples; `000000000000` is the
/// MiniStack placeholder already used by `fixtures.rs`.
pub const ALLOWED_ACCOUNT_IDS: &[&str] = &["123456789012", "210987654321", "000000000000"];

/// The corpus. Ordering is stable and load-bearing: [`full_envelope`] emits
/// them in this order, so expected bodies stay predictable.
pub const RECORDS: &[CorpusRecord] = &[
    CorpusRecord {
        name: "sts-assume-role-service-role",
        event_source: "sts.amazonaws.com",
        event_name: "AssumeRole",
        notes: "Full sessionContext chain; `resources` is an ARRAY, so a rule \
                pointing at `resources.ARN` must resolve to None (never a match).",
        event_id: "5f2a8c1e-3d47-4b9a-8e1f-6c0d2a4b7e93",
        request_id: "b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e",
        json: r#"{"eventVersion":"1.09","userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLEID123456:aws-sdk-session-1717171717","arn":"arn:aws:sts::123456789012:assumed-role/service-role/pipeline-runner/aws-sdk-session-1717171717","accountId":"123456789012","accessKeyId":"ASIAEXAMPLEKEY12345","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"AROAEXAMPLEID123456","arn":"arn:aws:iam::123456789012:role/service-role/pipeline-runner","accountId":"123456789012","userName":"pipeline-runner"},"attributes":{"creationDate":"2026-07-29T09:14:22Z","mfaAuthenticated":"false"}}},"eventTime":"2026-07-29T09:14:23Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRole","awsRegion":"eu-west-1","sourceIPAddress":"192.0.2.44","userAgent":"aws-sdk-go/1.55.5 (go1.22.4; linux; amd64)","requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/service-role/deploy","roleSessionName":"aws-sdk-1717171717","durationSeconds":3600},"responseElements":{"credentials":{"accessKeyId":"ASIAEXAMPLEKEY67890","expiration":"Jul 29, 2026 10:14:23 AM","sessionToken":"IQoJb3JpZ2luX2VjEXAMPLETOKEN"},"assumedRoleUser":{"assumedRoleId":"AROAEXAMPLEID654321:aws-sdk-1717171717","arn":"arn:aws:sts::123456789012:assumed-role/deploy/aws-sdk-1717171717"}},"requestID":"b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e","eventID":"5f2a8c1e-3d47-4b9a-8e1f-6c0d2a4b7e93","readOnly":true,"resources":[{"accountId":"123456789012","type":"AWS::IAM::Role","ARN":"arn:aws:iam::123456789012:role/service-role/deploy"}],"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"123456789012","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","clientProvidedHostHeader":"sts.eu-west-1.amazonaws.com"}}"#,
    },
    CorpusRecord {
        name: "sts-assume-role-with-web-identity-irsa",
        event_source: "sts.amazonaws.com",
        event_name: "AssumeRoleWithWebIdentity",
        notes: "IRSA shape: userIdentity has NO accountId and carries \
                webIdFederationData; matches the example ruleset's \
                'Kubernetes Service Accounts' rule via requestParameters.roleArn.",
        event_id: "9c4e7b20-1a68-4f3d-b5c7-2e8a09d1f4b6",
        request_id: "7d8e9f00-1122-4334-9556-778899aabbcc",
        json: r#"{"eventVersion":"1.08","userIdentity":{"type":"WebIdentityUser","principalId":"arn:aws:iam::123456789012:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sts.amazonaws.com:system:serviceaccount:prod:checkout","userName":"system:serviceaccount:prod:checkout","identityProvider":"arn:aws:iam::123456789012:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"},"eventTime":"2026-07-29T09:15:02Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRoleWithWebIdentity","awsRegion":"eu-west-1","sourceIPAddress":"198.51.100.17","userAgent":"aws-sdk-java/2.25.11 Linux/5.10.220 OpenJDK_64-Bit_Server_VM/21.0.3","requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/prod-eks-checkout-irsa-role","roleSessionName":"checkout-7f9c4b8d6-x2klm","durationSeconds":3600},"responseElements":{"subjectFromWebIdentityToken":"system:serviceaccount:prod:checkout","audience":"sts.amazonaws.com","provider":"arn:aws:iam::123456789012:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"},"requestID":"7d8e9f00-1122-4334-9556-778899aabbcc","eventID":"9c4e7b20-1a68-4f3d-b5c7-2e8a09d1f4b6","readOnly":true,"resources":[{"accountId":"123456789012","type":"AWS::IAM::Role","ARN":"arn:aws:iam::123456789012:role/prod-eks-checkout-irsa-role"}],"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"123456789012","eventCategory":"Management"}"#,
    },
    CorpusRecord {
        name: "kms-decrypt-from-eks",
        event_source: "kms.amazonaws.com",
        event_name: "Decrypt",
        notes: "The canonical high-volume drop: matches the example ruleset's \
                'EKS KMS Operations' on eventName + eventSource + \
                sourceIPAddress. encryptionContext is a nested free-form map.",
        event_id: "1b3d5f70-9a2c-4e6b-8d0f-3a5c7e9b1d2f",
        request_id: "aabbccdd-eeff-4011-a223-34455667788a",
        json: r#"{"eventVersion":"1.09","userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLEID999999:i-0abc123def4567890","arn":"arn:aws:sts::123456789012:assumed-role/eks-node-group/i-0abc123def4567890","accountId":"123456789012","accessKeyId":"ASIAEXAMPLEKEY99999","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"AROAEXAMPLEID999999","arn":"arn:aws:iam::123456789012:role/eks-node-group","accountId":"123456789012","userName":"eks-node-group"},"attributes":{"creationDate":"2026-07-29T06:02:11Z","mfaAuthenticated":"false"}}},"eventTime":"2026-07-29T09:15:44Z","eventSource":"kms.amazonaws.com","eventName":"Decrypt","awsRegion":"eu-west-1","sourceIPAddress":"eks.amazonaws.com","userAgent":"eks.amazonaws.com","requestParameters":{"encryptionContext":{"aws:eks:cluster-name":"prod-euw1","kubernetes.io/namespace":"kube-system","aws:secretsmanager:secret":"prod/db/password"},"encryptionAlgorithm":"SYMMETRIC_DEFAULT"},"responseElements":null,"requestID":"aabbccdd-eeff-4011-a223-34455667788a","eventID":"1b3d5f70-9a2c-4e6b-8d0f-3a5c7e9b1d2f","readOnly":true,"resources":[{"accountId":"123456789012","type":"AWS::KMS::Key","ARN":"arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"}],"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"123456789012","eventCategory":"Management"}"#,
    },
    CorpusRecord {
        name: "ec2-describe-launch-template-versions",
        event_source: "ec2.amazonaws.com",
        event_name: "DescribeLaunchTemplateVersions",
        notes: "Matches the example ruleset's 'EKS Nodegroup Launch Templates' \
                rule, whose fourth condition is a 4-level dot path — the \
                deepest resolution the engine performs.",
        event_id: "3e6a9c12-4b7d-4a80-9c3e-5f1b8d2a6c40",
        request_id: "11223344-5566-4778-899a-abbccddeeff0",
        json: r#"{"eventVersion":"1.09","userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLEIDNODEGRP:EKS","arn":"arn:aws:sts::123456789012:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS","accountId":"123456789012","accessKeyId":"ASIAEXAMPLEKEYNODEG","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"AROAEXAMPLEIDNODEGRP","arn":"arn:aws:iam::123456789012:role/aws-service-role/eks-nodegroup.amazonaws.com/AWSServiceRoleForAmazonEKSNodegroup","accountId":"123456789012","userName":"AWSServiceRoleForAmazonEKSNodegroup"},"attributes":{"creationDate":"2026-07-29T09:00:00Z","mfaAuthenticated":"false"}},"invokedBy":"eks-nodegroup.amazonaws.com"},"eventTime":"2026-07-29T09:16:01Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeLaunchTemplateVersions","awsRegion":"eu-west-1","sourceIPAddress":"eks-nodegroup.amazonaws.com","userAgent":"eks-nodegroup.amazonaws.com","requestParameters":{"launchTemplateId":"lt-0a1b2c3d4e5f67890","maxResults":200,"versionsSet":{"items":[{"version":"3"}]}},"responseElements":null,"requestID":"11223344-5566-4778-899a-abbccddeeff0","eventID":"3e6a9c12-4b7d-4a80-9c3e-5f1b8d2a6c40","readOnly":true,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"123456789012","eventCategory":"Management"}"#,
    },
    CorpusRecord {
        name: "s3-get-object-terraform-state",
        event_source: "s3.amazonaws.com",
        event_name: "GetObject",
        notes: "Data event (eventCategory Data, managementEvent false) with \
                additionalEventData carrying NUMBERS and a boolean — the \
                resolver must render those as text, not skip them.",
        event_id: "7a1c3e59-2d84-4f16-b7a0-9c5e3b1d8f24",
        request_id: "EXAMPLE7A1C3E5900",
        json: r#"{"eventVersion":"1.10","userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLEIDTFCI01:terraform-run-abc123","arn":"arn:aws:sts::123456789012:assumed-role/terraform-ci/terraform-run-abc123","accountId":"123456789012","accessKeyId":"ASIAEXAMPLEKEYTFCI0","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"AROAEXAMPLEIDTFCI01","arn":"arn:aws:iam::123456789012:role/terraform-ci","accountId":"123456789012","userName":"terraform-ci"},"attributes":{"creationDate":"2026-07-29T09:10:00Z","mfaAuthenticated":"false"}}},"eventTime":"2026-07-29T09:16:30Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"eu-west-1","sourceIPAddress":"192.0.2.201","userAgent":"APN/1.0 HashiCorp/1.0 Terraform/1.9.2 (+https://www.terraform.io) aws-sdk-go/1.44.122","requestParameters":{"bucketName":"tfstate-prod-euw1","Host":"tfstate-prod-euw1.s3.eu-west-1.amazonaws.com","key":"env/prod/network/terraform.tfstate"},"responseElements":null,"additionalEventData":{"SignatureVersion":"SigV4","CipherSuite":"TLS_AES_128_GCM_SHA256","bytesTransferredIn":0,"AuthenticationMethod":"AuthHeader","x-amz-id-2":"EXAMPLEqWm1sQ1TppAaDL0F0k7ZoRnBLQdVcRZ2E4hDwaBDeExAmPlE=","bytesTransferredOut":184320,"SSEApplied":"SSE_S3"},"requestID":"EXAMPLE7A1C3E5900","eventID":"7a1c3e59-2d84-4f16-b7a0-9c5e3b1d8f24","readOnly":true,"resources":[{"type":"AWS::S3::Object","ARN":"arn:aws:s3:::tfstate-prod-euw1/env/prod/network/terraform.tfstate"},{"accountId":"123456789012","type":"AWS::S3::Bucket","ARN":"arn:aws:s3:::tfstate-prod-euw1"}],"eventType":"AwsApiCall","managementEvent":false,"recipientAccountId":"123456789012","eventCategory":"Data"}"#,
    },
    CorpusRecord {
        name: "signin-console-login-mfa",
        event_source: "signin.amazonaws.com",
        event_name: "ConsoleLogin",
        notes: "requestParameters is NULL — a rule pointing at \
                requestParameters.x must resolve to None, not match. The \
                eventSource this project's own fixtures use, so it also keeps \
                the corpus compatible with existing rule sets.",
        event_id: "c8f4a260-7b13-4e95-a2d6-0b8e4c1f7a35",
        request_id: "d4e5f6a7-b8c9-40d1-92e3-f4a5b6c7d8e9",
        json: r#"{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDAEXAMPLEUSERID01","arn":"arn:aws:iam::123456789012:user/break-glass","accountId":"123456789012","userName":"break-glass"},"eventTime":"2026-07-29T09:17:12Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.203","userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15","requestParameters":null,"responseElements":{"ConsoleLogin":"Success"},"additionalEventData":{"LoginTo":"https://eu-west-1.console.aws.amazon.com/console/home?region=eu-west-1&state=hashArgs","MobileVersion":"No","MFAIdentifier":"arn:aws:iam::123456789012:mfa/break-glass","MFAUsed":"Yes"},"requestID":"d4e5f6a7-b8c9-40d1-92e3-f4a5b6c7d8e9","eventID":"c8f4a260-7b13-4e95-a2d6-0b8e4c1f7a35","readOnly":false,"eventType":"AwsConsoleSignIn","managementEvent":true,"recipientAccountId":"123456789012","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","clientProvidedHostHeader":"signin.aws.amazon.com"}}"#,
    },
    CorpusRecord {
        name: "logs-put-log-events-from-lambda",
        event_source: "logs.amazonaws.com",
        event_name: "PutLogEvents",
        notes: "Matches two example rules at once ('Lambda CloudWatch Logs' \
                and 'VPC Flow Logs' share eventName) — proves a record is \
                attributed to exactly ONE rule, the reconciliation identity \
                sum(RuleDrops) == RecordsDropped.",
        event_id: "2d9b6f83-5c07-4a21-8e4b-1f3a7d0c9e56",
        request_id: "f0e1d2c3-b4a5-4968-8778-695a4b3c2d1e",
        json: r#"{"eventVersion":"1.09","userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLEIDLAMBDA1:api-handler","arn":"arn:aws:sts::123456789012:assumed-role/api-handler-role/api-handler","accountId":"123456789012","accessKeyId":"ASIAEXAMPLEKEYLAMBD","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"AROAEXAMPLEIDLAMBDA1:aws-lambda-api-handler","arn":"arn:aws:iam::123456789012:role/api-handler-role","accountId":"123456789012","userName":"api-handler-role"},"attributes":{"creationDate":"2026-07-29T09:12:00Z","mfaAuthenticated":"false"}}},"eventTime":"2026-07-29T09:17:45Z","eventSource":"logs.amazonaws.com","eventName":"PutLogEvents","awsRegion":"eu-west-1","sourceIPAddress":"192.0.2.99","userAgent":"aws-sdk-nodejs/2.1691.0 linux/v20.15.0 exec-env/AWS_Lambda_nodejs20.x","requestParameters":{"logGroupName":"/aws/lambda/api-handler","logStreamName":"2026/07/29/[$LATEST]a1b2c3d4e5f64758697a8b9c0d1e2f30","sequenceToken":"49590000000000000000000000000000000000000000000000000001"},"responseElements":{"nextSequenceToken":"49590000000000000000000000000000000000000000000000000002"},"requestID":"f0e1d2c3-b4a5-4968-8778-695a4b3c2d1e","eventID":"2d9b6f83-5c07-4a21-8e4b-1f3a7d0c9e56","readOnly":false,"eventType":"AwsApiCall","managementEvent":false,"recipientAccountId":"123456789012","eventCategory":"Data"}"#,
    },
    CorpusRecord {
        name: "iam-create-user-security-relevant",
        event_source: "iam.amazonaws.com",
        event_name: "CreateUser",
        notes: "The control case: a record no sane ruleset drops. If a change \
                makes THIS disappear from the output, filtering has inverted.",
        event_id: "6b0d2f47-8a91-4c35-b6e8-4d2c9f0a7b13",
        request_id: "9a8b7c6d-5e4f-4321-a098-7b6c5d4e3f2a",
        json: r#"{"eventVersion":"1.09","userIdentity":{"type":"IAMUser","principalId":"AIDAEXAMPLEADMIN001","arn":"arn:aws:iam::123456789012:user/platform-admin","accountId":"123456789012","accessKeyId":"AKIAEXAMPLEADMIN001","sessionContext":{"attributes":{"creationDate":"2026-07-29T08:55:00Z","mfaAuthenticated":"true"}}},"eventTime":"2026-07-29T09:18:03Z","eventSource":"iam.amazonaws.com","eventName":"CreateUser","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.14","userAgent":"aws-cli/2.17.9 Python/3.11.9 Darwin/24.5.0 source/arm64","requestParameters":{"userName":"contractor-jw","tags":[{"key":"owner","value":"platform"},{"key":"expires","value":"2026-10-01"}]},"responseElements":{"user":{"path":"/","userName":"contractor-jw","userId":"AIDAEXAMPLECONTRACT","arn":"arn:aws:iam::123456789012:user/contractor-jw","createDate":"Jul 29, 2026 9:18:03 AM"}},"requestID":"9a8b7c6d-5e4f-4321-a098-7b6c5d4e3f2a","eventID":"6b0d2f47-8a91-4c35-b6e8-4d2c9f0a7b13","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"123456789012","eventCategory":"Management"}"#,
    },
    CorpusRecord {
        name: "escapes-and-unicode",
        event_source: "lambda.amazonaws.com",
        event_name: "Invoke",
        notes: "THE verbatim-copy prover. errorMessage mixes escaped quotes, \
                doubled backslashes, a tab, literal non-ASCII UTF-8, and — the \
                load-bearing part — two escapes serde_json decodes but never \
                re-emits: \\u00fc (rendered as literal ü) and \\/ (rendered as \
                a bare /). Those two diverge under ANY serde_json feature set, \
                including preserve_order, which is what makes this record a \
                reliable detector rather than an accident of key ordering.",
        event_id: "8e5c1a94-0f62-4d78-9b31-7a6e2c4f0d85",
        request_id: "c3d4e5f6-a7b8-4c90-b1d2-e3f4a5b6c7d8",
        json: r#"{"eventVersion":"1.09","userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLEIDINVOKE1:caller","arn":"arn:aws:sts::123456789012:assumed-role/invoker/caller","accountId":"123456789012","accessKeyId":"ASIAEXAMPLEKEYINVOK"},"eventTime":"2026-07-29T09:18:41Z","eventSource":"lambda.amazonaws.com","eventName":"Invoke","awsRegion":"eu-central-1","sourceIPAddress":"192.0.2.7","userAgent":"aws-cli/2.17.9 Python/3.11.9 Linux/6.8.0 exec-env/CloudShell","errorCode":"InvalidParameterValueException","errorMessage":"Der Wert \"payload\" ist ung\u00fcltig — expected JSON, got: {\"a\":\"b\\\\c\"}\tsee https:\/\/example.com\/docs ☁ 日本語 😀","requestParameters":{"functionName":"arn:aws:lambda:eu-central-1:123456789012:function:report-générateur","invocationType":"RequestResponse","qualifier":"$LATEST"},"responseElements":null,"requestID":"c3d4e5f6-a7b8-4c90-b1d2-e3f4a5b6c7d8","eventID":"8e5c1a94-0f62-4d78-9b31-7a6e2c4f0d85","readOnly":false,"eventType":"AwsApiCall","managementEvent":false,"recipientAccountId":"123456789012","eventCategory":"Data"}"#,
    },
    CorpusRecord {
        name: "numeric-edge-cases",
        event_source: "cloudwatch.amazonaws.com",
        event_name: "PutMetricData",
        notes: "Numbers a re-serializer would rewrite: a trailing-zero float, \
                an exponent, negative zero, a high-precision decimal, and an \
                integer past f64's exact range. serde_json normalizes several \
                of these; RawValue must not touch any.",
        event_id: "4f7b0d26-9c58-4e13-a740-2b9d6f8c1e07",
        request_id: "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d",
        json: r#"{"eventVersion":"1.09","userIdentity":{"type":"AWSService","invokedBy":"monitoring.amazonaws.com"},"eventTime":"2026-07-29T09:19:07Z","eventSource":"cloudwatch.amazonaws.com","eventName":"PutMetricData","awsRegion":"eu-west-1","sourceIPAddress":"monitoring.amazonaws.com","userAgent":"monitoring.amazonaws.com","requestParameters":{"namespace":"Prod/Checkout","metricData":[{"metricName":"Latency","value":1.0,"unit":"Milliseconds"},{"metricName":"Ratio","value":1.5e-7,"unit":"None"},{"metricName":"Drift","value":-0.0,"unit":"None"},{"metricName":"Precise","value":0.1000000000000000055511151231257827,"unit":"None"},{"metricName":"Counter","value":9007199254740993,"unit":"Count"}]},"responseElements":null,"requestID":"5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d","eventID":"4f7b0d26-9c58-4e13-a740-2b9d6f8c1e07","readOnly":false,"eventType":"AwsApiCall","managementEvent":false,"recipientAccountId":"123456789012","eventCategory":"Data"}"#,
    },
    CorpusRecord {
        name: "additional-event-data-as-json-string",
        event_source: "elasticfilesystem.amazonaws.com",
        event_name: "NewClientConnection",
        notes: "additionalEventData is a STRING that happens to contain JSON — \
                a real CloudTrail shape. A dot path into it resolves to the \
                whole string, never to its inner fields; the resolver must not \
                try to parse it.",
        event_id: "0a3c8e71-6d24-4b59-8f07-5c1e9a2b4d68",
        request_id: "e1f2a3b4-c5d6-4e78-9a0b-1c2d3e4f5a6b",
        json: r#"{"eventVersion":"1.08","userIdentity":{"type":"AWSAccount","principalId":"AROAEXAMPLEIDEFS001:session","accountId":"210987654321"},"eventTime":"2026-07-29T09:19:33Z","eventSource":"elasticfilesystem.amazonaws.com","eventName":"NewClientConnection","awsRegion":"eu-west-1","sourceIPAddress":"192.0.2.130","userAgent":"elasticfilesystem.amazonaws.com","requestParameters":null,"responseElements":null,"additionalEventData":"{\"AWSAccountId\":\"210987654321\",\"MountTargetId\":\"fsmt-0a1b2c3d\",\"ClientIpAddress\":\"192.0.2.130\",\"Permissions\":\"ReadWrite\"}","requestID":"e1f2a3b4-c5d6-4e78-9a0b-1c2d3e4f5a6b","eventID":"0a3c8e71-6d24-4b59-8f07-5c1e9a2b4d68","readOnly":true,"eventType":"AwsServiceEvent","managementEvent":true,"recipientAccountId":"123456789012","eventCategory":"Management"}"#,
    },
    CorpusRecord {
        name: "cross-account-recipient",
        event_source: "guardduty.amazonaws.com",
        event_name: "GetFindings",
        notes: "An organization trail record whose recipientAccountId differs \
                from userIdentity.accountId, and whose eventSource appears \
                nowhere else — index coverage for a source with no rule, which \
                must fall through to the `always` bucket only.",
        event_id: "b2e6d049-3f81-4a27-95c0-8d4b1f7a3e62",
        request_id: "0f1e2d3c-4b5a-4695-8778-89a0b1c2d3e4",
        json: r#"{"eventVersion":"1.09","userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLEIDSECOPS1:secops","arn":"arn:aws:sts::210987654321:assumed-role/security-audit/secops","accountId":"210987654321","accessKeyId":"ASIAEXAMPLEKEYSECOP","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"AROAEXAMPLEIDSECOPS1","arn":"arn:aws:iam::210987654321:role/security-audit","accountId":"210987654321","userName":"security-audit"},"attributes":{"creationDate":"2026-07-29T09:00:00Z","mfaAuthenticated":"true"}}},"eventTime":"2026-07-29T09:20:15Z","eventSource":"guardduty.amazonaws.com","eventName":"GetFindings","awsRegion":"eu-west-1","sourceIPAddress":"198.51.100.88","userAgent":"aws-cli/2.17.9 Python/3.11.9 Linux/6.8.0","requestParameters":{"detectorId":"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d","findingIds":["7f8e9d0c1b2a3948576655443322110f"]},"responseElements":null,"requestID":"0f1e2d3c-4b5a-4695-8778-89a0b1c2d3e4","eventID":"b2e6d049-3f81-4a27-95c0-8d4b1f7a3e62","readOnly":true,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"123456789012","eventCategory":"Management"}"#,
    },
    CorpusRecord {
        name: "insight-record",
        event_source: "ec2.amazonaws.com",
        event_name: "RunInstances",
        notes: "A CloudTrail Insights record: eventCategory Insight, no \
                userIdentity at all, and an insightDetails subtree. Objects of \
                this shape live under /CloudTrail-Insight/ and are excluded by \
                key — but the engine must survive one arriving anyway.",
        event_id: "d7c3b8f5-2a46-4019-8e7d-6b0a5c3f9e14",
        request_id: "8b7a6959-4837-4261-b504-3f2e1d0c9b8a",
        json: r#"{"eventVersion":"1.08","eventTime":"2026-07-29T09:21:00Z","awsRegion":"eu-west-1","eventID":"d7c3b8f5-2a46-4019-8e7d-6b0a5c3f9e14","eventType":"AwsCloudTrailInsight","recipientAccountId":"123456789012","sharedEventID":"a1b2c3d4-e5f6-4708-9a1b-2c3d4e5f6a7b","eventCategory":"Insight","eventSource":"ec2.amazonaws.com","eventName":"RunInstances","requestID":"8b7a6959-4837-4261-b504-3f2e1d0c9b8a","insightDetails":{"state":"Start","eventSource":"ec2.amazonaws.com","eventName":"RunInstances","insightType":"ApiCallRateInsight","insightContext":{"statistics":{"baseline":{"average":0.0166666667},"insight":{"average":41.0},"insightDuration":5,"baselineDuration":10080},"attributions":[{"attribute":"userIdentityArn","insight":[{"value":"arn:aws:sts::123456789012:assumed-role/autoscaler/scale-out","average":41.0}],"baseline":[{"value":"arn:aws:sts::123456789012:assumed-role/autoscaler/scale-out","average":0.0142857143}]}]}}}"#,
    },
    CorpusRecord {
        name: "minimal-legacy-record",
        event_source: "support.amazonaws.com",
        event_name: "DescribeTrustedAdvisorChecks",
        notes: "The floor: an old, sparse record with almost no optional \
                fields. Rules referencing fields it lacks must evaluate FALSE, \
                not match-by-absence — the difference between dropping nothing \
                and dropping everything.",
        event_id: "f5a1e73c-8b09-4d62-a418-3c7e5b2d9f06",
        request_id: "2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f",
        json: r#"{"eventVersion":"1.02","userIdentity":{"type":"Root","principalId":"123456789012","arn":"arn:aws:iam::123456789012:root","accountId":"123456789012"},"eventTime":"2026-07-29T09:21:38Z","eventSource":"support.amazonaws.com","eventName":"DescribeTrustedAdvisorChecks","awsRegion":"us-east-1","sourceIPAddress":"192.0.2.1","userAgent":"console.amazonaws.com","requestID":"2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f","eventID":"f5a1e73c-8b09-4d62-a418-3c7e5b2d9f06","eventType":"AwsApiCall","recipientAccountId":"123456789012"}"#,
    },
];

/// A realistic S3 object key, plus whether the **default** `source`
/// include/exclude regexes should select it.
#[derive(Debug, Clone, Copy)]
pub struct CorpusKey {
    pub key: &'static str,
    /// Expected result of `KeyFilter::accepts` under `Source::default()`:
    /// include `\.json\.gz$`, exclude
    /// `(/CloudTrail-Digest/|/CloudTrail-Insight/|/$)`.
    pub accepted_by_default: bool,
    pub notes: &'static str,
}

/// Keys as CloudTrail actually lays them out, including the three prefixes the
/// default exclude regex exists to reject.
pub const KEYS: &[CorpusKey] = &[
    CorpusKey {
        key: "AWSLogs/123456789012/CloudTrail/eu-west-1/2026/07/29/123456789012_CloudTrail_eu-west-1_20260729T0915Z_a1B2c3D4e5F6g7H8.json.gz",
        accepted_by_default: true,
        notes: "The ordinary single-account trail object.",
    },
    CorpusKey {
        key: "AWSLogs/o-a1b2c3d4e5/123456789012/CloudTrail/eu-west-1/2026/07/29/123456789012_CloudTrail_eu-west-1_20260729T0915Z_Z9y8X7w6V5u4T3s2.json.gz",
        accepted_by_default: true,
        notes: "Organization trail: an extra o-* segment before the account.",
    },
    CorpusKey {
        key: "prefix/with/custom/root/AWSLogs/123456789012/CloudTrail/us-east-1/2026/07/29/123456789012_CloudTrail_us-east-1_20260729T0920Z_QqWwEeRrTtYyUuIi.json.gz",
        accepted_by_default: true,
        notes: "A trail configured with an S3 key prefix.",
    },
    CorpusKey {
        key: "AWSLogs/123456789012/CloudTrail-Digest/eu-west-1/2026/07/29/123456789012_CloudTrail-Digest_eu-west-1_prod_eu-west-1_20260729T091500Z.json.gz",
        accepted_by_default: false,
        notes: "Digest file: valid .json.gz, entirely different schema. \
                Processing one would rewrite it as an unrecognized object.",
    },
    CorpusKey {
        key: "AWSLogs/123456789012/CloudTrail-Insight/eu-west-1/2026/07/29/123456789012_CloudTrail-Insight_eu-west-1_20260729T0921Z_InSiGhT0123456789.json.gz",
        accepted_by_default: false,
        notes: "Insights object: Records of a different shape (see the \
                insight-record corpus entry).",
    },
    CorpusKey {
        key: "AWSLogs/123456789012/CloudTrail/eu-west-1/2026/07/29/",
        accepted_by_default: false,
        notes: "The zero-byte directory marker the console creates; excluded \
                by the trailing-slash branch AND by the .json.gz include.",
    },
    CorpusKey {
        key: "AWSLogs/123456789012/CloudTrail/eu-west-1/2026/07/29/123456789012_CloudTrail_eu-west-1_20260729T0915Z_a1B2c3D4e5F6g7H8.json",
        accepted_by_default: false,
        notes: "Uncompressed sibling: fails the include regex.",
    },
];

/// Wraps `records` in the `{"Records":[...]}` envelope **verbatim**, joined
/// exactly the way `buffer_run` and `stream_run` assemble their output — so an
/// expected body built here is byte-comparable with what the pipeline writes.
pub fn envelope<'a, I>(records: I) -> String
where
    I: IntoIterator<Item = &'a CorpusRecord>,
{
    let bodies: Vec<&str> = records.into_iter().map(|r| r.json).collect();
    envelope_of(&bodies)
}

/// [`envelope`] over record bodies that are not corpus constants — the output
/// of [`scale_records`], or a hand-built variant. Kept public so a test can
/// build an *expected* body the same way the pipeline builds the real one,
/// instead of re-hardcoding the envelope format in the test.
pub fn envelope_of<S: AsRef<str>>(bodies: &[S]) -> String {
    let joined = bodies
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<&str>>()
        .join(",");
    format!("{{\"Records\":[{joined}]}}")
}

/// The whole corpus as one object, in [`RECORDS`] order.
pub fn full_envelope() -> String {
    envelope(RECORDS)
}

/// Every record, for callers that want to iterate rather than name one.
pub fn records() -> &'static [CorpusRecord] {
    RECORDS
}

/// The envelope of every record satisfying `keep` — i.e. the output expected
/// from an engine that drops exactly the complement. Returns `None` when
/// nothing is kept, which is the pipeline's `NothingKept` outcome rather than
/// an empty envelope.
pub fn envelope_where(keep: impl Fn(&CorpusRecord) -> bool) -> Option<String> {
    let kept: Vec<&CorpusRecord> = RECORDS.iter().filter(|r| keep(r)).collect();
    if kept.is_empty() {
        None
    } else {
        Some(envelope(kept))
    }
}

/// Look up a record by [`CorpusRecord::name`]. Panics on a typo rather than
/// silently testing nothing.
pub fn find(name: &str) -> &'static CorpusRecord {
    RECORDS
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no corpus record named {name:?}"))
}

/// An object of `count` records, cycling the corpus and giving every copy a
/// distinct `eventID` and `requestID`.
///
/// The uniqueness is the point. A large fixture built by repeating one record
/// compresses far better than real CloudTrail, so any test that reasons about
/// `stream_threshold_bytes` against such a fixture is reasoning about a ratio
/// production never produces. Cycling 14 distinct records and perturbing two
/// identifiers per copy lands in the neighbourhood of a real object's ratio.
pub fn scale_envelope(count: usize) -> String {
    envelope_of(&scale_records(count))
}

/// The bodies [`scale_envelope`] wraps, in order. A test that expects a
/// *filtered* large object builds its expectation from these — same bytes, own
/// predicate — rather than trying to reconstruct the substitutions.
pub fn scale_records(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| with_unique_ids(&RECORDS[i % RECORDS.len()], i))
        .collect()
}

/// One corpus record with fresh identifiers. Both substitutions are asserted:
/// a silently-missed replacement would produce a uniform fixture again, which
/// is exactly the failure mode [`scale_envelope`] exists to avoid.
fn with_unique_ids(record: &CorpusRecord, idx: usize) -> String {
    let event_id = synthetic_id("ev", idx);
    let request_id = synthetic_id("rq", idx);

    assert!(
        record.json.contains(record.event_id),
        "corpus record {:?} declares event_id {:?}, which does not appear in its json",
        record.name,
        record.event_id
    );
    let out = record.json.replace(record.event_id, &event_id);

    assert!(
        record.json.contains(record.request_id),
        "corpus record {:?} declares request_id {:?}, which does not appear in its json",
        record.name,
        record.request_id
    );
    out.replace(record.request_id, &request_id)
}

/// A UUID-shaped identifier derived from `idx`. Deterministic — the corpus
/// must produce identical bytes on every run so failures are reproducible.
fn synthetic_id(tag: &str, idx: usize) -> String {
    format!("{tag}{idx:06}-0000-4000-8000-{idx:012}")
}

/// Every 12-digit run in the corpus that is not an allowed documentation
/// account ID. A non-empty result means someone pasted in real data.
///
/// Deliberately blunt: it flags any 12-digit sequence, so a realistic-looking
/// sequence number would trip it too. That is the right bias — a false
/// positive costs one edit, a false negative publishes a customer's account.
pub fn unexpected_account_ids() -> Vec<String> {
    let mut found = Vec::new();
    for record in RECORDS {
        for candidate in twelve_digit_runs(record.json) {
            if !ALLOWED_ACCOUNT_IDS.contains(&candidate.as_str()) {
                found.push(format!("{}: {candidate}", record.name));
            }
        }
    }
    for key in KEYS {
        for candidate in twelve_digit_runs(key.key) {
            if !ALLOWED_ACCOUNT_IDS.contains(&candidate.as_str()) {
                found.push(format!("{}: {candidate}", key.key));
            }
        }
    }
    found
}

/// Maximal runs of exactly 12 digits (a longer run is not an account ID, and
/// splitting one into 12-digit windows would report noise).
fn twelve_digit_runs(text: &str) -> Vec<String> {
    let mut runs = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else {
            if current.len() == 12 {
                runs.push(std::mem::take(&mut current));
            }
            current.clear();
        }
    }
    if current.len() == 12 {
        runs.push(current);
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn every_record_is_valid_json_and_matches_its_declared_metadata() {
        for record in RECORDS {
            let parsed: Value = serde_json::from_str(record.json).unwrap_or_else(|e| {
                panic!("corpus record {:?} is not valid JSON: {e}", record.name)
            });
            assert_eq!(
                parsed["eventSource"].as_str(),
                Some(record.event_source),
                "corpus record {:?}: eventSource disagrees with its declared metadata",
                record.name
            );
            assert_eq!(
                parsed["eventName"].as_str(),
                Some(record.event_name),
                "corpus record {:?}: eventName disagrees with its declared metadata",
                record.name
            );
            assert_eq!(
                parsed["eventID"].as_str(),
                Some(record.event_id),
                "corpus record {:?}: eventID disagrees with its declared metadata",
                record.name
            );
        }
    }

    #[test]
    fn record_names_are_unique() {
        let mut names: Vec<&str> = RECORDS.iter().map(|r| r.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "corpus record names must be unique");
    }

    /// The corpus is only useful as a verbatim reference if its records are
    /// *not* what serde would have produced — otherwise it cannot distinguish
    /// a copy from a re-serialization.
    ///
    /// Two records are named explicitly rather than counting divergences over
    /// the whole corpus, because how many records diverge depends on the build:
    /// with `serde_json/preserve_order` off, every record differs by key order
    /// alone and the count is meaningless; with it on (which workspace feature
    /// unification turns on here), only genuine value-level differences remain.
    /// These two diverge either way — see the bait tokens below.
    #[test]
    fn the_designated_records_differ_from_serdes_rendering() {
        for name in ["escapes-and-unicode", "numeric-edge-cases"] {
            let record = find(name);
            let parsed: Value = serde_json::from_str(record.json).expect("valid JSON");
            assert_ne!(
                serde_json::to_string(&parsed).expect("re-serializable"),
                record.json,
                "corpus record {name:?} is byte-identical to serde's rendering, \
                 so it can no longer detect a re-serializing regression"
            );
        }
    }

    /// The specific bytes the test above depends on, pinned by name so that
    /// "tidying up" a fixture fails here with an explanation instead of
    /// silently defusing the verbatim-copy check.
    ///
    /// `\u00fc` and `\/` are the load-bearing pair: serde_json *decodes* both
    /// and re-emits them as `ü` and `/`, so their presence guarantees
    /// divergence under any feature set. The rest are checked because they are
    /// the escapes most likely to be "simplified" by a well-meaning edit.
    #[test]
    fn the_normalization_bait_is_still_in_place() {
        let escapes = find("escapes-and-unicode").json;
        for (bait, why) in [
            (r"\u00fc", "serde re-emits this as a literal ü"),
            (r"\/", "serde re-emits this as a bare /"),
            (r"\t", "a tab escape"),
            (r"\\", "a doubled backslash"),
            ("😀", "literal non-ASCII UTF-8 outside the BMP"),
        ] {
            assert!(
                escapes.contains(bait),
                "escapes-and-unicode must keep {bait:?} ({why})"
            );
        }

        let numbers = find("numeric-edge-cases").json;
        for (bait, why) in [
            ("1.0", "a trailing-zero float"),
            ("1.5e-7", "an exponent serde renders differently"),
            ("-0.0", "negative zero"),
            ("9007199254740993", "an integer past f64's exact range"),
        ] {
            assert!(
                numbers.contains(bait),
                "numeric-edge-cases must keep {bait} ({why})"
            );
        }
    }

    #[test]
    fn the_envelope_is_valid_json_containing_every_record() {
        let parsed: Value = serde_json::from_str(&full_envelope()).expect("envelope must parse");
        assert_eq!(
            parsed["Records"].as_array().map(Vec::len),
            Some(RECORDS.len())
        );
    }

    #[test]
    fn envelope_where_keeping_nothing_is_none() {
        assert!(envelope_where(|_| false).is_none());
    }

    #[test]
    fn scale_envelope_gives_every_copy_distinct_identifiers() {
        let body = scale_envelope(40);
        let parsed: Value = serde_json::from_str(&body).expect("scaled envelope must parse");
        let records = parsed["Records"].as_array().expect("Records array");
        assert_eq!(records.len(), 40);

        let mut ids: Vec<&str> = records
            .iter()
            .map(|r| {
                r["eventID"]
                    .as_str()
                    .expect("every record keeps an eventID")
            })
            .collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(
            before,
            ids.len(),
            "scale_envelope produced duplicate eventIDs, so the fixture \
             compresses unrealistically well"
        );
    }

    #[test]
    fn the_corpus_contains_no_real_looking_account_ids() {
        let found = unexpected_account_ids();
        assert!(
            found.is_empty(),
            "the corpus must only contain documentation account IDs \
             ({ALLOWED_ACCOUNT_IDS:?}); found {found:?}"
        );
    }

    #[test]
    fn keys_cover_both_sides_of_the_default_filter() {
        assert!(KEYS.iter().any(|k| k.accepted_by_default));
        assert!(KEYS.iter().any(|k| !k.accepted_by_default));
    }
}
