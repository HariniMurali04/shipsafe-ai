"""Integration tests for POST /api/analyze and POST /api/verify endpoints."""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "samples"


@pytest.fixture
def insecure_sample() -> dict:
    with open(SAMPLES_DIR / "insecure_s3_config.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def secure_sample() -> dict:
    with open(SAMPLES_DIR / "secure_s3_config.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_api_analyze_insecure_payload(insecure_sample: dict) -> None:
    """Test POST /api/analyze returns 200 with structured findings."""
    response = client.post("/api/analyze", json=insecure_sample)

    assert response.status_code == 200
    data = response.json()
    assert data["evaluation_verdict"] == "RISKS_DETECTED"
    assert data["total_findings"] > 0
    assert data["confirmed_risks_count"] > 0
    assert "findings" in data

    # Check evidence presence
    for finding in data["findings"]:
        assert "evidence" in finding
        assert "why_it_matters" in finding
        assert "remediation" in finding
        assert "confidence" in finding


def test_api_analyze_wrapped_payload(insecure_sample: dict) -> None:
    """Test POST /api/analyze supports {"configuration": {...}} payload wrapper."""
    response = client.post("/api/analyze", json={"configuration": insecure_sample})

    assert response.status_code == 200
    data = response.json()
    assert data["evaluation_verdict"] == "RISKS_DETECTED"


def test_api_analyze_secure_payload(secure_sample: dict) -> None:
    """Test POST /api/analyze returns NO_EVALUATED_RISKS_DETECTED on secure sample."""
    response = client.post("/api/analyze", json=secure_sample)

    assert response.status_code == 200
    data = response.json()
    assert data["evaluation_verdict"] == "NO_EVALUATED_RISKS_DETECTED"
    assert data["confirmed_risks_count"] == 0


def test_api_analyze_malformed_validation_error() -> None:
    """Test POST /api/analyze returns 422 with useful details when payload lacks configuration_type."""
    response = client.post("/api/analyze", json={"configurations": {}})

    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert data["detail"]["error"] == "ConfigurationValidationError"
    assert "configuration_type" in data["detail"]["message"]


def test_api_verify_resolved(secure_sample: dict) -> None:
    """Test POST /api/verify correctly verifies resolved findings on updated config."""
    payload = {
        "configuration": secure_sample,
        "rule_ids": ["S3-PAB-001", "S3-ENC-001"],
    }
    response = client.post("/api/verify", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["overall_verification_status"] == "ALL_RESOLVED"
    assert data["resolved_count"] == 2
    assert data["still_present_count"] == 0

    for result in data["verification_results"]:
        assert result["status"] == "Resolved"


def test_api_verify_still_present(insecure_sample: dict) -> None:
    """Test POST /api/verify accurately detects still-present violations."""
    payload = {
        "configuration": insecure_sample,
        "rule_ids": ["S3-PAB-001"],
    }
    response = client.post("/api/verify", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["overall_verification_status"] == "UNRESOLVED"
    assert data["still_present_count"] == 1
    assert data["verification_results"][0]["status"] == "Still present"
    assert data["verification_results"][0]["evidence"] is not None


def test_api_verify_unable_to_verify(secure_sample: dict) -> None:
    """Test POST /api/verify handles unrecognized rules with Unable to verify."""
    payload = {
        "configuration": secure_sample,
        "rule_ids": ["NON-EXISTENT-RULE"],
    }
    response = client.post("/api/verify", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["unable_to_verify_count"] == 1
    assert data["verification_results"][0]["status"] == "Unable to verify"


def test_api_analyze_raw_invalid_json() -> None:
    """Test POST /api/analyze with unparseable raw JSON returns 422 InvalidJSON."""
    response = client.post(
        "/api/analyze",
        content="{invalid json string here: true",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "InvalidJSON"


def test_api_verify_raw_invalid_json() -> None:
    """Test POST /api/verify with unparseable raw JSON returns 422 InvalidJSON."""
    response = client.post(
        "/api/verify",
        content="{malformed payload",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "InvalidJSON"


def test_api_analyze_non_dict_payload() -> None:
    """Test POST /api/analyze with JSON array returns 422 InvalidPayload."""
    response = client.post("/api/analyze", json=["invalid", "array"])
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "InvalidPayload"


def test_api_verify_non_dict_payload() -> None:
    """Test POST /api/verify with JSON array returns 422 InvalidPayload."""
    response = client.post("/api/verify", json=["invalid", "array"])
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "InvalidPayload"


def test_api_analyze_unsupported_configuration_type() -> None:
    """Test POST /api/analyze with non-S3 configuration_type returns 422."""
    payload = {
        "configuration_type": "AWS::EC2::Instance",
        "configurations": {},
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "ConfigurationValidationError"
    assert "Unsupported configuration_type" in data["detail"]["message"]


def test_api_analyze_missing_configurations_block() -> None:
    """Test POST /api/analyze missing configurations block returns 422."""
    payload = {
        "configuration_type": "AWS::S3::Bucket",
        "metadata": {"resource_id": "test"},
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "ConfigurationValidationError"
    assert "configurations" in data["detail"]["message"]


def test_api_verify_partial_resolution(insecure_sample: dict) -> None:
    """Test POST /api/verify detects partial resolution when only some rules pass."""
    # Modify insecure_sample to fix encryption but leave public access block broken
    partially_fixed = json.loads(json.dumps(insecure_sample))
    partially_fixed["configurations"]["server_side_encryption"] = {
        "rules": [
            {
                "apply_server_side_encryption_by_default": {
                    "sse_algorithm": "AES256"
                }
            }
        ]
    }

    payload = {
        "configuration": partially_fixed,
        "rule_ids": ["S3-ENC-001", "S3-PAB-001"],
    }
    response = client.post("/api/verify", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_verification_status"] == "PARTIALLY_RESOLVED"
    assert data["resolved_count"] == 1
    assert data["still_present_count"] == 1

