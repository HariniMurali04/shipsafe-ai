"""API route definitions for ShipSafe AI core endpoints."""

from typing import Any
from fastapi import APIRouter, HTTPException, Request

from app.engine.analyzer import analyze_s3_configuration, verify_s3_configuration
from app.engine.models import AnalysisResponse, Finding, VerificationResponse
from app.engine.validator import ConfigurationValidationError
from app.explainer.provider import ExplanationResult
from app.explainer.service import SecurityExplanationService
from app.schemas import FeatureItem, FeaturesResponse, HealthResponse

router = APIRouter()
explainer_service = SecurityExplanationService()

# Catalog of ShipSafe AI platform features with explicit completion status
PLATFORM_FEATURES: list[FeatureItem] = [
    FeatureItem(
        id="api-health-check",
        name="Runtime Health & Diagnostics",
        description="Provides live API availability, application version, and system status verification.",
        status="implemented",
        endpoint="/api/health",
    ),
    FeatureItem(
        id="feature-discovery",
        name="Capabilities Discovery API",
        description="Exposes current and planned security auditing capabilities to clients and frontend UIs.",
        status="implemented",
        endpoint="/api/features",
    ),
    FeatureItem(
        id="s3-static-analyzer",
        name="Synthetic AWS S3 Security Rule Engine",
        description="Detects public read/write exposure, missing encryption, disabled versioning, and open ACLs on synthetic S3 bucket configurations without requiring live AWS credentials.",
        status="implemented",
        endpoint="/api/analyze",
    ),
    FeatureItem(
        id="diff-verifier",
        name="Config Diff & Fix Verification",
        description="Reruns security rules against modified configurations to verify full resolution before deployment.",
        status="implemented",
        endpoint="/api/verify",
    ),
    FeatureItem(
        id="risk-explainer",
        name="Security Risk & Impact Explainer",
        description="Explains why detected configurations violate cloud security standards and the business impact of potential exposure.",
        status="implemented",
        endpoint="/api/assistant/chat",
    ),
    FeatureItem(
        id="remediation-generator",
        name="Remediation & Secure JSON Generator",
        description="Generates actionable remediation guidance and production-ready secure configuration snippets.",
        status="implemented",
        endpoint="/api/assistant/chat",
    ),
    FeatureItem(
        id="simulated-alexa-assistant",
        name="ShipSafe Assistant (Simulated Alexa+)",
        description="Conversational voice-first simulation guiding developers through analysis, risk explanations, and verification.",
        status="implemented",
        endpoint="/api/assistant/chat",
    ),
    FeatureItem(
        id="optional-bedrock-explainer",
        name="Amazon Bedrock AI Explanation Provider",
        description="Optional generative explanation layer using Amazon Bedrock with automatic, zero-cost deterministic fallback.",
        status="implemented",
        endpoint="/api/explainer/status",
    ),
]


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Application Health Status",
    description="Returns valid JSON indicating that ShipSafe AI backend service is running and responsive.",
)
async def get_health() -> HealthResponse:
    """Return application operational health status and metadata."""
    return HealthResponse(
        status="healthy",
        app_name="ShipSafe AI",
        tagline="Secure Every Change Before It Ships.",
        version="0.1.0",
    )


@router.get(
    "/features",
    response_model=FeaturesResponse,
    summary="Application Capabilities",
    description="Returns the currently implemented and planned application capabilities.",
)
async def get_features() -> FeaturesResponse:
    """Return catalog of implemented and planned platform features."""
    implemented = [f for f in PLATFORM_FEATURES if f.status == "implemented"]
    return FeaturesResponse(
        total_features=len(PLATFORM_FEATURES),
        implemented_count=len(implemented),
        features=PLATFORM_FEATURES,
    )


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    summary="Analyze Synthetic AWS S3 Configuration",
    description=(
        "Performs deterministic static security analysis on a synthetic AWS S3 configuration JSON. "
        "Returns categorized findings (confirmed risks, missing evidence, informational) with exact evidence."
    ),
)
async def analyze_configuration(request: Request) -> AnalysisResponse:
    """Analyze S3 bucket configuration and return structured security findings."""
    try:
        body: Any = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "InvalidJSON",
                "message": f"Malformed JSON payload: {str(e)}",
            },
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=422,
            detail={
                "error": "InvalidPayload",
                "message": "Input payload must be a JSON object (dictionary).",
            },
        )

    # Support either {"configuration": {...}} or direct {...} payload
    config_payload = (
        body["configuration"]
        if "configuration" in body and isinstance(body["configuration"], dict)
        else body
    )

    try:
        return analyze_s3_configuration(config_payload)
    except ConfigurationValidationError as e:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "ConfigurationValidationError",
                "message": e.message,
                "details": e.details,
            },
        )


@router.post(
    "/verify",
    response_model=VerificationResponse,
    summary="Verify Remediation Against S3 Configuration",
    description=(
        "Reruns security rules against updated configuration to verify whether targeted findings "
        "or rule IDs are resolved ('Resolved', 'Still present', or 'Unable to verify')."
    ),
)
async def verify_configuration(request: Request) -> VerificationResponse:
    """Rerun security rules against corrected configuration to verify resolution."""
    try:
        body: Any = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "InvalidJSON",
                "message": f"Malformed JSON payload: {str(e)}",
            },
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=422,
            detail={
                "error": "InvalidPayload",
                "message": "Input payload must be a JSON object (dictionary).",
            },
        )

    config_payload = (
        body["configuration"]
        if "configuration" in body and isinstance(body["configuration"], dict)
        else body
    )
    finding_ids = body.get("finding_ids")
    rule_ids = body.get("rule_ids")

    try:
        return verify_s3_configuration(
            config_payload,
            target_finding_ids=finding_ids,
            target_rule_ids=rule_ids,
        )
    except ConfigurationValidationError as e:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "ConfigurationValidationError",
                "message": e.message,
                "details": e.details,
            },
        )


@router.get(
    "/explainer/status",
    summary="Security Explanation Provider Status",
    description="Returns configuration status of the explanation provider (Amazon Bedrock / Deterministic Fallback). Never exposes secrets.",
)
async def get_explainer_status() -> dict[str, Any]:
    """Return runtime status of the security explanation providers."""
    return explainer_service.get_provider_status()


@router.post(
    "/explain/finding",
    response_model=ExplanationResult,
    summary="Explain a Security Finding",
    description="Explains an individual security finding using Amazon Bedrock if enabled, or deterministic fallback.",
)
async def explain_finding_endpoint(finding: Finding) -> ExplanationResult:
    """Generate an explainable risk rationale for a concrete security finding."""
    return explainer_service.explain_finding(finding)
