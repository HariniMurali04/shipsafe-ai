"""Pydantic data models for the ShipSafe Assistant conversational interface."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from app.engine.models import AnalysisResponse, VerificationResponse


class ActionChip(BaseModel):
    """Suggested quick command chip for the user interface."""

    label: str
    prompt: str


class AssistantMessage(BaseModel):
    """Individual message in the conversation stream."""

    role: Literal["user", "assistant", "system"]
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cards: Optional[List[Dict[str, Any]]] = None
    suggested_prompts: Optional[List[str]] = None


class AssistantChatRequest(BaseModel):
    """User request sent to POST /api/assistant/chat."""

    message: str = Field(..., description="User's typed conversational command or query")
    session_id: Optional[str] = Field(default="default-session", description="Session identifier for browser context")
    current_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Active configuration JSON currently loaded in the user session",
    )
    active_finding_ids: Optional[List[str]] = Field(
        default=None,
        description="Finding IDs from the most recent analysis run",
    )
    corrected_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Candidate remediated configuration JSON for verification",
    )


class AssistantChatResponse(BaseModel):
    """Assistant's conversational reply payload."""

    reply: str
    intent: str
    agentic_step: str = Field(
        ...,
        description="Current step in the controlled 9-step security verification workflow",
    )
    explanation_mode: Literal["deterministic_template", "ai_augmented"] = Field(
        default="deterministic_template",
        description="Indicates whether the explanation was generated via deterministic templates or an AI model",
    )
    is_sample_data: bool = Field(
        default=True,
        description="Indicates whether the analyzed data is based on synthetic demonstration samples",
    )
    cards: Optional[List[Dict[str, Any]]] = None
    suggested_prompts: List[str] = Field(default_factory=list)
    analysis_data: Optional[AnalysisResponse] = None
    verification_data: Optional[VerificationResponse] = None
    notice: str = "Simulated Alexa+ assistant experience for demonstration purposes only. Not connected to official Alexa services."
