"""Modular explanation generator for ShipSafe Assistant.

Integrates with SecurityExplanationService to support:
1. Pure deterministic, template-based explanations grounded in real backend findings (default, zero cost).
2. Optional Amazon Bedrock AI explanation provider when explicitly configured.
Never fabricates findings, evidence, or verification success.
"""

from typing import Any, Dict, Tuple
from app.engine.models import AnalysisResponse, Finding, VerificationResponse
from app.explainer.service import SecurityExplanationService

_explanation_service = SecurityExplanationService()


def generate_deterministic_finding_explanation(finding: Finding) -> str:
    """Generate a clear, conversational explanation of a specific finding using its evidence."""
    res = _explanation_service.fallback_provider.explain_finding(finding)
    return res.explanation


def generate_deterministic_risk_summary(analysis: AnalysisResponse) -> str:
    """Synthesize the architectural risk posture from actual findings."""
    res = _explanation_service.fallback_provider.explain_analysis_posture(analysis)
    return res.explanation


def generate_deterministic_verification_summary(verification: VerificationResponse) -> str:
    """Synthesize verification results from actual re-run checks."""
    if verification.overall_verification_status == "ALL_RESOLVED":
        return (
            f"Verification complete! All {verification.resolved_count} targeted issues in '{verification.resource_id}' "
            f"were re-evaluated and confirmed Resolved. The configuration now complies with our evaluated baseline."
        )
    elif verification.overall_verification_status == "PARTIALLY_RESOLVED":
        return (
            f"Verification resulted in Partial Resolution. {verification.resolved_count} issue(s) were resolved, "
            f"but {verification.still_present_count} issue(s) are Still Present and require attention."
        )
    else:
        return (
            f"Verification indicates issues remain Unresolved. {verification.still_present_count} check(s) still failed "
            f"on the updated configuration. Review the active findings to adjust the JSON parameters."
        )


def explain_conversational_response(
    topic: str,
    context_data: Dict[str, Any],
) -> Tuple[str, str]:
    """Provide a modular conversational explanation.

    Returns:
        Tuple of (explanation_text, explanation_mode)
    """
    target_finding = context_data.get("target_finding")
    analysis = context_data.get("analysis")
    verification = context_data.get("verification")

    if topic == "most_serious_issue" and target_finding:
        res = _explanation_service.explain_finding(target_finding)
        mode = res.provider_used if not res.is_fallback else "deterministic_template"
        return res.explanation, mode

    elif topic == "explain_risk" and analysis:
        res = _explanation_service.explain_analysis_posture(analysis)
        mode = res.provider_used if not res.is_fallback else "deterministic_template"
        return res.explanation, mode

    elif topic == "verify_resolution" and verification:
        return generate_deterministic_verification_summary(verification), "deterministic_template"

    elif topic == "evidence" and target_finding:
        evidence_str = str(target_finding.evidence)
        return (
            f"Concrete evidence extracted from {target_finding.rule_id}: {evidence_str}. "
            f"This represents the exact values found in your configuration payload."
        ), "deterministic_template"

    return "I evaluated your configuration against the deterministic security rules.", "deterministic_template"
