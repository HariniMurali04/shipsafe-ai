"""Unified Explanation Service for ShipSafe AI.

Orchestrates deterministic template explanations and optional Amazon Bedrock AI.
Guarantees resilient fallback under any failure, timeout, or missing credential condition.
"""

import logging
from typing import Any, Dict, Optional

from app.engine.models import AnalysisResponse, Finding
from app.explainer.bedrock_provider import AmazonBedrockExplanationProvider, BedrockInvocationError
from app.explainer.deterministic_provider import DeterministicExplanationProvider
from app.explainer.provider import BaseExplanationProvider, ExplanationResult

logger = logging.getLogger("shipsafe.explainer.service")


class SecurityExplanationService:
    """Service providing explainable cloud security insights with transparent fallbacks."""

    def __init__(
        self,
        bedrock_provider: Optional[BaseExplanationProvider] = None,
        fallback_provider: Optional[BaseExplanationProvider] = None,
    ) -> None:
        self.fallback_provider = fallback_provider or DeterministicExplanationProvider()
        self.bedrock_provider = bedrock_provider or AmazonBedrockExplanationProvider()

    def get_provider_status(self) -> Dict[str, Any]:
        """Return safe, non-sensitive provider configuration metadata."""
        is_bedrock_configured = self.bedrock_provider.is_available
        bedrock_inst = self.bedrock_provider if isinstance(self.bedrock_provider, AmazonBedrockExplanationProvider) else None

        return {
            "active_provider": "amazon_bedrock" if is_bedrock_configured else "deterministic_template",
            "bedrock_enabled": getattr(bedrock_inst, "enabled", False),
            "bedrock_available": is_bedrock_configured,
            "bedrock_region": getattr(bedrock_inst, "region", "none"),
            "bedrock_model_id": getattr(bedrock_inst, "model_id", "none"),
            "fallback_provider": self.fallback_provider.name,
            "cost_notice": "Bedrock incurs AWS per-token API charges when enabled. Deterministic fallback is 100% free.",
        }

    def explain_finding(self, finding: Finding) -> ExplanationResult:
        """Explain an individual finding, attempting Bedrock if enabled, falling back safely."""
        if self.bedrock_provider.is_available:
            try:
                return self.bedrock_provider.explain_finding(finding)
            except BedrockInvocationError as e:
                logger.info("Bedrock unavailable (%s). Using deterministic fallback.", e.error_code)
                fallback_res = self.fallback_provider.explain_finding(finding)
                fallback_res.is_fallback = True
                fallback_res.fallback_reason = e.message
                return fallback_res
            except Exception as e:
                logger.warning("Unexpected provider error: %s (%s). Using deterministic fallback.", type(e), e)
                fallback_res = self.fallback_provider.explain_finding(finding)
                fallback_res.is_fallback = True
                fallback_res.fallback_reason = "AI provider encountered an error; reverted to deterministic template."
                return fallback_res

        return self.fallback_provider.explain_finding(finding)

    def explain_analysis_posture(self, analysis: AnalysisResponse) -> ExplanationResult:
        """Explain overall posture, attempting Bedrock if enabled, falling back safely."""
        if self.bedrock_provider.is_available:
            try:
                return self.bedrock_provider.explain_analysis_posture(analysis)
            except BedrockInvocationError as e:
                logger.info("Bedrock unavailable (%s). Using deterministic fallback.", e.error_code)
                fallback_res = self.fallback_provider.explain_analysis_posture(analysis)
                fallback_res.is_fallback = True
                fallback_res.fallback_reason = e.message
                return fallback_res
            except Exception as e:
                logger.warning("Unexpected provider error. Using deterministic fallback.")
                fallback_res = self.fallback_provider.explain_analysis_posture(analysis)
                fallback_res.is_fallback = True
                fallback_res.fallback_reason = "AI provider encountered an error; reverted to deterministic template."
                return fallback_res

        return self.fallback_provider.explain_analysis_posture(analysis)
