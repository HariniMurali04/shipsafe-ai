"""Deterministic explanation provider for ShipSafe AI (Default Fallback).

Grounded exclusively in real backend findings, extracted evidence, and remediation steps.
Zero network dependencies, zero cost, and zero hallucinations.
"""

from app.engine.models import AnalysisResponse, Finding
from app.explainer.provider import BaseExplanationProvider, ExplanationResult


class DeterministicExplanationProvider(BaseExplanationProvider):
    """Default fallback provider generating structured, deterministic explanations."""

    @property
    def name(self) -> str:
        return "deterministic_template"

    @property
    def is_available(self) -> bool:
        return True

    def explain_finding(self, finding: Finding) -> ExplanationResult:
        """Deterministically explain a single finding using its actual evidence."""
        evidence_str = ", ".join(f"{k}: {v}" for k, v in finding.evidence.items() if k != "has_condition")

        text = (
            f"Regarding {finding.title} ({finding.rule_id}) [Severity: {finding.severity.value}]: "
            f"In your configuration, I detected {evidence_str}. "
            f"{finding.why_it_matters} "
            f"Remediation step: {finding.remediation}"
        )

        return ExplanationResult(
            explanation=text,
            provider_used="deterministic_template",
            is_fallback=False,
            disclaimer="Deterministic explanation derived strictly from static evaluation rules and input evidence.",
        )

    def explain_analysis_posture(self, analysis: AnalysisResponse) -> ExplanationResult:
        """Deterministically explain the overall architectural risk posture."""
        confirmed = [f for f in analysis.findings if f.finding_type.value == "CONFIRMED_RISK"]
        missing = [f for f in analysis.findings if f.finding_type.value == "MISSING_EVIDENCE"]

        if not confirmed and not missing:
            text = (
                f"Good news! In {analysis.resource_id}, no confirmed risks were detected by the evaluated static checks. "
                f"All {len(analysis.evaluated_rules)} static security checks passed. "
                f"Note that {analysis.informational_count} informational observation(s) were recorded."
            )
        else:
            top_finding = confirmed[0] if confirmed else None
            top_rule = f"{top_finding.title} ({top_finding.rule_id})" if top_finding else "Omitted Configuration Blocks"
            why_matter = f" {top_finding.why_it_matters}" if top_finding else ""
            text = (
                f"I analyzed synthetic bucket '{analysis.resource_id}' and identified {len(confirmed)} confirmed security risks. "
                f"The most critical vulnerability is {top_rule}.{why_matter} "
                f"Combined with other unhardened controls, this bucket is not deployment-ready."
            )

        return ExplanationResult(
            explanation=text,
            provider_used="deterministic_template",
            is_fallback=False,
            disclaimer="Deterministic summary derived strictly from evaluated static rule results.",
        )
