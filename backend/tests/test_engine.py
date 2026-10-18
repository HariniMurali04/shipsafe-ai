"""Unit tests for the ShipSafe AI security analysis and verification engine."""

import json
from pathlib import Path
import pytest
from app.engine.analyzer import analyze_s3_configuration, verify_s3_configuration
from app.engine.models import VerificationStatus
from app.engine.validator import ConfigurationValidationError

SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "samples"


@pytest.fixture
def insecure_config() -> dict:
    with open(SAMPLES_DIR / "insecure_s3_config.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def secure_config() -> dict:
    with open(SAMPLES_DIR / "secure_s3_config.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_analyze_insecure_sample(insecure_config: dict) -> None:
    """Verify that insecure sample produces confirmed risk findings."""
    result = analyze_s3_configuration(insecure_config)

    assert result.evaluation_verdict == "RISKS_DETECTED"
    assert result.confirmed_risks_count > 0
    assert result.total_findings > 0

    rule_ids = [f.rule_id for f in result.findings]
    assert "S3-PAB-001" in rule_ids
    assert "S3-POL-001" in rule_ids
    assert "S3-ACL-001" in rule_ids
    assert "S3-ENC-001" in rule_ids
    assert "S3-VER-001" in rule_ids
    assert "S3-LOG-001" in rule_ids

    # Every finding has non-empty evidence
    for f in result.findings:
        assert f.evidence is not None
        assert len(f.evidence) > 0
        assert f.why_it_matters != ""
        assert f.remediation != ""

    # Disclaimer is present
    assert "not guarantee complete security" in result.disclaimer


def test_analyze_secure_sample(secure_config: dict) -> None:
    """Verify that secure sample produces no confirmed risks."""
    result = analyze_s3_configuration(secure_config)

    assert result.evaluation_verdict == "NO_EVALUATED_RISKS_DETECTED"
    assert result.confirmed_risks_count == 0
    assert result.missing_evidence_count == 0

    # Informational findings may be present
    assert result.informational_count >= 1

    # Ensure system does not claim complete cloud security
    assert "not guarantee complete security" in result.disclaimer


def test_engine_determinism(insecure_config: dict) -> None:
    """Verify that executing analysis multiple times produces identical results."""
    run1 = analyze_s3_configuration(insecure_config)
    run2 = analyze_s3_configuration(insecure_config)

    assert run1.total_findings == run2.total_findings
    assert run1.confirmed_risks_count == run2.confirmed_risks_count
    assert run1.evaluation_verdict == run2.evaluation_verdict

    finding_ids_1 = [f.finding_id for f in run1.findings]
    finding_ids_2 = [f.finding_id for f in run2.findings]
    assert finding_ids_1 == finding_ids_2


def test_validation_rejects_non_dict() -> None:
    """Validation must reject primitive types or lists."""
    with pytest.raises(ConfigurationValidationError) as exc:
        analyze_s3_configuration(["not", "a", "dict"])
    assert "JSON object" in exc.value.message


def test_validation_rejects_missing_config_type() -> None:
    """Validation must reject payload without configuration_type."""
    with pytest.raises(ConfigurationValidationError) as exc:
        analyze_s3_configuration({"configurations": {}})
    assert "configuration_type" in exc.value.message


def test_validation_rejects_unsupported_config_type() -> None:
    """Validation must reject non-S3 configuration types."""
    with pytest.raises(ConfigurationValidationError) as exc:
        analyze_s3_configuration({
            "configuration_type": "AWS::EC2::Instance",
            "configurations": {},
        })
    assert "Unsupported configuration_type" in exc.value.message


def test_validation_rejects_missing_configurations_block() -> None:
    """Validation must reject payload without configurations dictionary."""
    with pytest.raises(ConfigurationValidationError) as exc:
        analyze_s3_configuration({"configuration_type": "AWS::S3::Bucket"})
    assert "configurations" in exc.value.message


def test_verify_resolved_findings(secure_config: dict) -> None:
    """Test rechecking previously broken rules against the secure config reports 'Resolved'."""
    targets = ["S3-PAB-001", "S3-ENC-001", "S3-ACL-001"]
    res = verify_s3_configuration(secure_config, target_rule_ids=targets)

    assert res.overall_verification_status == "ALL_RESOLVED"
    assert res.resolved_count == 3
    assert res.still_present_count == 0

    for item in res.verification_results:
        assert item.status == VerificationStatus.RESOLVED


def test_verify_still_present_findings(insecure_config: dict) -> None:
    """Test rechecking broken rules against insecure config reports 'Still present'."""
    targets = ["S3-PAB-001", "S3-ENC-001"]
    res = verify_s3_configuration(insecure_config, target_rule_ids=targets)

    assert res.overall_verification_status == "UNRESOLVED"
    assert res.still_present_count == 2
    assert res.resolved_count == 0

    for item in res.verification_results:
        assert item.status == VerificationStatus.STILL_PRESENT
        assert item.evidence is not None


def test_verify_unrecognized_rule(secure_config: dict) -> None:
    """Test target rule ID not recognized by engine returns 'Unable to verify'."""
    res = verify_s3_configuration(secure_config, target_rule_ids=["S3-NONEXISTENT-999"])

    assert res.unable_to_verify_count == 1
    item = res.verification_results[0]
    assert item.status == VerificationStatus.UNABLE_TO_VERIFY
    assert "not match any recognized rule ID" in item.explanation
