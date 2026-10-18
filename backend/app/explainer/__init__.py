"""ShipSafe AI Security Explanation Module."""

from app.explainer.bedrock_provider import (
    AmazonBedrockExplanationProvider,
    BedrockInvocationError,
)
from app.explainer.deterministic_provider import DeterministicExplanationProvider
from app.explainer.provider import BaseExplanationProvider, ExplanationResult
from app.explainer.service import SecurityExplanationService

__all__ = [
    "BaseExplanationProvider",
    "ExplanationResult",
    "DeterministicExplanationProvider",
    "AmazonBedrockExplanationProvider",
    "BedrockInvocationError",
    "SecurityExplanationService",
]
