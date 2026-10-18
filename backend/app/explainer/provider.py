"""Provider interface and schemas for the ShipSafe AI Security Explanation Service."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from app.engine.models import AnalysisResponse, Finding


class ExplanationResult(BaseModel):
    """Result returned by an explanation provider."""

    explanation: str = Field(..., description="Conversational or technical explanation text")
    provider_used: Literal["deterministic_template", "amazon_bedrock"] = Field(
        ...,
        description="Identifies which explanation provider produced this output",
    )
    is_fallback: bool = Field(
        default=False,
        description="True if an external provider failed or was unavailable and fallback was triggered",
    )
    fallback_reason: Optional[str] = Field(
        default=None,
        description="Explanation of why fallback occurred (if applicable)",
    )
    disclaimer: str = Field(
        default="Explanation is strictly scoped to evaluated static configuration parameters.",
        description="Standard scope and safety notice",
    )


class BaseExplanationProvider(ABC):
    """Abstract base provider for explaining security findings."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the provider."""
        pass

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check whether the provider is configured and available for use."""
        pass

    @abstractmethod
    def explain_finding(self, finding: Finding) -> ExplanationResult:
        """Explain an individual security finding."""
        pass

    @abstractmethod
    def explain_analysis_posture(self, analysis: AnalysisResponse) -> ExplanationResult:
        """Explain the overall architectural posture of an evaluated configuration."""
        pass
