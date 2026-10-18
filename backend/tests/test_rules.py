"""Unit tests for individual deterministic security rules."""

import pytest
from app.engine.models import Confidence, FindingType, Severity
from app.engine.rules import (
    check_access_control_list,
    check_bucket_policy,
    check_public_access_block,
    check_server_access_logging,
    check_server_side_encryption,
    check_unsupported_fields,
    check_versioning,
)


def test_rule_pab_disabled_flags() -> None:
    """Test S3-PAB-001 fires when public access block flags are false."""
    configs = {
        "public_access_block": {
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        }
    }
    findings = check_public_access_block(configs, "test-bucket")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "S3-PAB-001"
    assert finding.severity == Severity.CRITICAL
    assert finding.finding_type == FindingType.CONFIRMED_RISK
    assert len(finding.evidence["disabled_flags"]) == 4


def test_rule_pab_missing_block() -> None:
    """Test S3-PAB-MISSING fires when public_access_block is missing."""
    configs = {}
    findings = check_public_access_block(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-PAB-MISSING"
    assert findings[0].finding_type == FindingType.MISSING_EVIDENCE
    assert findings[0].severity == Severity.HIGH


def test_rule_pab_fully_enabled() -> None:
    """Test PAB check produces zero findings when all flags are enabled."""
    configs = {
        "public_access_block": {
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        }
    }
    findings = check_public_access_block(configs, "test-bucket")
    assert len(findings) == 0


def test_rule_bucket_policy_public_allow() -> None:
    """Test S3-POL-001 fires when statement allows public principal without condition."""
    configs = {
        "bucket_policy": {
            "version": "2012-10-17",
            "statement": [
                {
                    "sid": "AllowAllPublic",
                    "effect": "Allow",
                    "principal": "*",
                    "action": ["s3:GetObject"],
                    "resource": "arn:aws:s3:::test-bucket/*",
                }
            ],
        }
    }
    findings = check_bucket_policy(configs, "test-bucket")
    rule_ids = [f.rule_id for f in findings]
    assert "S3-POL-001" in rule_ids
    assert "S3-POL-002" in rule_ids  # Also flags missing TLS deny statement


def test_rule_bucket_policy_tls_enforced() -> None:
    """Test S3-POL-002 is satisfied when TLS deny condition is present."""
    configs = {
        "bucket_policy": {
            "version": "2012-10-17",
            "statement": [
                {
                    "sid": "DenyInsecureTransport",
                    "effect": "Deny",
                    "principal": "*",
                    "action": "s3:*",
                    "resource": "arn:aws:s3:::test-bucket/*",
                    "condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }
    }
    findings = check_bucket_policy(configs, "test-bucket")
    rule_ids = [f.rule_id for f in findings]
    assert "S3-POL-001" not in rule_ids
    assert "S3-POL-002" not in rule_ids


def test_rule_acl_public_grant() -> None:
    """Test S3-ACL-001 fires when grants contain AllUsers URI."""
    configs = {
        "access_control_list": {
            "grants": [
                {
                    "grantee": {
                        "type": "Group",
                        "uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "permission": "READ",
                }
            ]
        }
    }
    findings = check_access_control_list(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-ACL-001"
    assert findings[0].finding_type == FindingType.CONFIRMED_RISK
    assert findings[0].severity == Severity.HIGH


def test_rule_acl_empty_grants() -> None:
    """Test S3-ACL-001 does not fire on private ACLs with empty grants."""
    configs = {"access_control_list": {"grants": []}}
    findings = check_access_control_list(configs, "test-bucket")
    assert len(findings) == 0


def test_rule_encryption_disabled_empty_rules() -> None:
    """Test S3-ENC-001 fires when rules list is empty."""
    configs = {"server_side_encryption": {"rules": []}}
    findings = check_server_side_encryption(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-ENC-001"
    assert findings[0].finding_type == FindingType.CONFIRMED_RISK


def test_rule_encryption_missing() -> None:
    """Test S3-ENC-MISSING fires when encryption block is omitted."""
    configs = {}
    findings = check_server_side_encryption(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-ENC-MISSING"
    assert findings[0].finding_type == FindingType.MISSING_EVIDENCE


def test_rule_encryption_enabled_info() -> None:
    """Test S3-ENC-INFO is returned as informational when KMS encryption is configured."""
    configs = {
        "server_side_encryption": {
            "rules": [
                {
                    "apply_server_side_encryption_by_default": {
                        "sse_algorithm": "aws:kms",
                        "kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/sample-key",
                    },
                    "bucket_key_enabled": True,
                }
            ]
        }
    }
    findings = check_server_side_encryption(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-ENC-INFO"
    assert findings[0].finding_type == FindingType.INFORMATIONAL


def test_rule_logging_disabled() -> None:
    """Test S3-LOG-001 fires when enabled is false."""
    configs = {"server_access_logging": {"enabled": False}}
    findings = check_server_access_logging(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-LOG-001"
    assert findings[0].severity == Severity.MEDIUM


def test_rule_logging_missing() -> None:
    """Test S3-LOG-MISSING fires when block is omitted."""
    configs = {}
    findings = check_server_access_logging(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-LOG-MISSING"
    assert findings[0].finding_type == FindingType.MISSING_EVIDENCE


def test_rule_logging_active_info() -> None:
    """Test S3-LOG-INFO is returned when logging is enabled with target bucket."""
    configs = {
        "server_access_logging": {
            "enabled": True,
            "target_bucket": "my-central-logs",
            "target_prefix": "app/",
        }
    }
    findings = check_server_access_logging(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-LOG-INFO"
    assert findings[0].finding_type == FindingType.INFORMATIONAL


def test_rule_versioning_suspended() -> None:
    """Test S3-VER-001 fires when status is Suspended."""
    configs = {"versioning": {"status": "Suspended"}}
    findings = check_versioning(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-VER-001"
    assert findings[0].severity == Severity.LOW


def test_rule_versioning_missing() -> None:
    """Test S3-VER-MISSING fires when block is omitted."""
    configs = {}
    findings = check_versioning(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-VER-MISSING"
    assert findings[0].finding_type == FindingType.MISSING_EVIDENCE


def test_rule_versioning_enabled() -> None:
    """Test versioning check passes when status is Enabled."""
    configs = {"versioning": {"status": "Enabled"}}
    findings = check_versioning(configs, "test-bucket")
    assert len(findings) == 0


def test_rule_unsupported_fields() -> None:
    """Test S3-CFG-UNSUPPORTED fires when unexpected keys are in configurations."""
    configs = {
        "public_access_block": {},
        "random_unsupported_vendor_key": {"foo": "bar"},
    }
    findings = check_unsupported_fields(configs, "test-bucket")
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-CFG-UNSUPPORTED"
    assert "random_unsupported_vendor_key" in findings[0].evidence["unrecognized_fields"]
