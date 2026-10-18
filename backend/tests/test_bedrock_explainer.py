"""Unit tests for the Optional Amazon Bedrock AI Explanation Provider and Fallback Service.

All external calls to Amazon Bedrock are strictly mocked using unittest.mock.
Zero live or paid AWS API requests are made during test execution.
"""

import io
import json
from unittest.mock import MagicMock, patch
import pytest
from botocore.exceptions import ClientError, ReadTimeoutError
from fastapi.testclient import TestClient

from app.engine.models import (
    AnalysisResponse,
    Confidence,
    Finding,
    FindingType,
    Severity,
)
from app.explainer.bedrock_provider import (
    AmazonBedrockExplanationProvider,
    BedrockInvocationError,
)
from app.explainer.deterministic_provider import DeterministicExplanationProvider
from app.explainer.service import SecurityExplanationService
from app.main import app

client = TestClient(app)


@pytest.fixture
def sample_finding() -> Finding:
    """Fixture providing a synthetic S3-PAB-001 finding."""
    return Finding(
        finding_id="S3-PAB-001-test",
        rule_id="S3-PAB-001",
        severity=Severity.CRITICAL,
        finding_type=FindingType.CONFIRMED_RISK,
        title="S3 Public Access Block Disabled",
        description="Public Access Block configuration is disabled or partially disabled.",
        evidence={
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        },
        why_it_matters="Leaving Public Access Block disabled exposes the bucket to inadvertent public exposure.",
        remediation="Enable all 4 Public Access Block flags.",
        confidence=Confidence.CERTAIN,
    )


@pytest.fixture
def sample_analysis(sample_finding: Finding) -> AnalysisResponse:
    """Fixture providing a synthetic AnalysisResponse."""
    return AnalysisResponse(
        resource_id="synthetic-insecure-bucket",
        configuration_type="AWS::S3::Bucket",
        evaluation_verdict="RISKS_DETECTED",
        total_findings=1,
        confirmed_risks_count=1,
        missing_evidence_count=0,
        informational_count=0,
        evaluated_rules=["S3-PAB-001"],
        findings=[sample_finding],
        disclaimer="Static analysis scope disclaimer",
    )


# ==============================================================================
# 1. Deterministic Fallback & Status Tests
# ==============================================================================

def test_default_service_uses_deterministic_fallback(sample_finding: Finding) -> None:
    """With BEDROCK_ENABLED unset or false, the service must use deterministic provider."""
    service = SecurityExplanationService()
    assert service.bedrock_provider.is_available is False

    res = service.explain_finding(sample_finding)
    assert res.provider_used == "deterministic_template"
    assert res.is_fallback is False
    assert "S3-PAB-001" in res.explanation
    assert "block_public_acls: False" in res.explanation
    assert "Deterministic explanation derived strictly" in res.disclaimer


def test_explainer_status_endpoint() -> None:
    """GET /api/explainer/status returns safe, non-sensitive provider metadata."""
    response = client.get("/api/explainer/status")
    assert response.status_code == 200
    data = response.json()

    assert data["active_provider"] in ("deterministic_template", "amazon_bedrock")
    assert "bedrock_enabled" in data
    assert "bedrock_available" in data
    assert "bedrock_region" in data
    assert "bedrock_model_id" in data
    assert "cost_notice" in data
    # Ensure no secret keys are exposed
    assert "secret" not in str(data).lower()
    assert "aws_access_key_id" not in str(data).lower()


def test_api_explain_finding_endpoint(sample_finding: Finding) -> None:
    """POST /api/explain/finding returns structured ExplanationResult."""
    response = client.post("/api/explain/finding", json=sample_finding.model_dump())
    assert response.status_code == 200
    data = response.json()

    assert data["provider_used"] in ("deterministic_template", "amazon_bedrock")
    assert "S3-PAB-001" in data["explanation"]
    assert "disclaimer" in data


# ==============================================================================
# 2. Mocked Bedrock Success Tests (Claude 3 & Titan)
# ==============================================================================

def test_bedrock_mocked_claude_success(monkeypatch, sample_finding: Finding) -> None:
    """Test successful AI explanation using Claude 3 Messages API format."""
    monkeypatch.setenv("BEDROCK_ENABLED", "true")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")

    mock_client = MagicMock()
    mock_response_body = io.BytesIO(
        json.dumps({
            "content": [
                {"type": "text", "text": "AI explanation: Public access flags are disabled, exposing objects to internet traffic."}
            ]
        }).encode("utf-8")
    )
    mock_client.invoke_model.return_value = {"body": mock_response_body}

    provider = AmazonBedrockExplanationProvider()
    provider._client = mock_client

    service = SecurityExplanationService(bedrock_provider=provider)
    res = service.explain_finding(sample_finding)

    assert res.provider_used == "amazon_bedrock"
    assert res.is_fallback is False
    assert "Public access flags are disabled" in res.explanation
    assert "AI explanation generated via Amazon Bedrock" in res.disclaimer


def test_bedrock_mocked_titan_success(monkeypatch, sample_finding: Finding) -> None:
    """Test successful AI explanation using Amazon Titan format."""
    monkeypatch.setenv("BEDROCK_ENABLED", "true")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "amazon.titan-text-express-v1")

    mock_client = MagicMock()
    mock_response_body = io.BytesIO(
        json.dumps({
            "results": [
                {"outputText": "Titan AI: This bucket lacks S3 Block Public Access controls."}
            ]
        }).encode("utf-8")
    )
    mock_client.invoke_model.return_value = {"body": mock_response_body}

    provider = AmazonBedrockExplanationProvider()
    provider._client = mock_client

    service = SecurityExplanationService(bedrock_provider=provider)
    res = service.explain_finding(sample_finding)

    assert res.provider_used == "amazon_bedrock"
    assert res.is_fallback is False
    assert "Titan AI" in res.explanation


def test_bedrock_mocked_analysis_posture_success(monkeypatch, sample_analysis: AnalysisResponse) -> None:
    """Test successful overall posture explanation via Bedrock."""
    monkeypatch.setenv("BEDROCK_ENABLED", "true")

    mock_client = MagicMock()
    mock_response_body = io.BytesIO(
        json.dumps({
            "content": [
                {"type": "text", "text": "Postural analysis: Synthetic bucket has 1 confirmed high-risk vulnerability."}
            ]
        }).encode("utf-8")
    )
    mock_client.invoke_model.return_value = {"body": mock_response_body}

    provider = AmazonBedrockExplanationProvider()
    provider._client = mock_client

    service = SecurityExplanationService(bedrock_provider=provider)
    res = service.explain_analysis_posture(sample_analysis)

    assert res.provider_used == "amazon_bedrock"
    assert res.is_fallback is False
    assert "Postural analysis" in res.explanation


# ==============================================================================
# 3. Resilient Fallback Tests (AccessDenied, Timeout, Errors)
# ==============================================================================

def test_bedrock_access_denied_fallback(monkeypatch, sample_finding: Finding) -> None:
    """When Bedrock access is denied, service must fall back cleanly without raising 500."""
    monkeypatch.setenv("BEDROCK_ENABLED", "true")

    mock_client = MagicMock()
    error_response = {
        "Error": {
            "Code": "AccessDeniedException",
            "Message": "User is not authorized to perform: bedrock:InvokeModel",
        }
    }
    mock_client.invoke_model.side_effect = ClientError(error_response, "InvokeModel")

    provider = AmazonBedrockExplanationProvider()
    provider._client = mock_client

    service = SecurityExplanationService(bedrock_provider=provider)
    res = service.explain_finding(sample_finding)

    # Must seamlessly fall back to deterministic provider
    assert res.provider_used == "deterministic_template"
    assert res.is_fallback is True
    assert "AccessDeniedException" in res.fallback_reason
    assert "S3-PAB-001" in res.explanation


def test_bedrock_timeout_fallback(monkeypatch, sample_finding: Finding) -> None:
    """When Bedrock times out, service must fall back cleanly without hanging."""
    monkeypatch.setenv("BEDROCK_ENABLED", "true")

    mock_client = MagicMock()
    mock_client.invoke_model.side_effect = ReadTimeoutError(
        endpoint_url="https://bedrock-runtime.us-east-1.amazonaws.com",
    )

    provider = AmazonBedrockExplanationProvider()
    provider._client = mock_client

    service = SecurityExplanationService(bedrock_provider=provider)
    res = service.explain_finding(sample_finding)

    assert res.provider_used == "deterministic_template"
    assert res.is_fallback is True
    assert "ReadTimeoutError" in res.fallback_reason or "failed" in res.fallback_reason
    assert "S3-PAB-001" in res.explanation


def test_bedrock_never_logs_secrets_in_error(monkeypatch) -> None:
    """Simulated error strings containing dummy credentials must never leak into fallback reasons."""
    monkeypatch.setenv("BEDROCK_ENABLED", "true")

    mock_client = MagicMock()
    # Simulate an error with sensitive AWS keys in raw text
    secret_key = "AKIAIOSFODNN7EXAMPLE"
    mock_client.invoke_model.side_effect = Exception(f"Failed with key {secret_key}")

    provider = AmazonBedrockExplanationProvider()
    provider._client = mock_client

    with pytest.raises(BedrockInvocationError) as exc_info:
        provider._invoke_model("Test prompt")

    # The raised BedrockInvocationError message must NOT contain the simulated secret
    assert secret_key not in exc_info.value.message
    assert "Bedrock invocation failed" in exc_info.value.message
