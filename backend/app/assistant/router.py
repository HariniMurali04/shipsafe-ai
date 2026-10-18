"""FastAPI Router for ShipSafe Assistant (Simulated Alexa+ Experience)."""

from fastapi import APIRouter
from app.assistant.models import AssistantChatRequest, AssistantChatResponse
from app.assistant.service import ShipSafeAssistantService

router = APIRouter(prefix="/assistant", tags=["ShipSafe Assistant"])
assistant_service = ShipSafeAssistantService()


@router.post(
    "/chat",
    response_model=AssistantChatResponse,
    summary="Chat with ShipSafe Assistant",
    description=(
        "Simulated Alexa+ assistant conversational endpoint. Processes natural language "
        "commands, executes deterministic security checks, explains findings, and verifies remediations."
    ),
)
async def chat_with_assistant(request: AssistantChatRequest) -> AssistantChatResponse:
    """Process a typed conversational message through the 9-step agentic workflow."""
    return assistant_service.handle_chat_message(request)


@router.get(
    "/prompts",
    summary="Get Suggested Conversational Prompts",
    description="Returns pre-configured suggested prompts for the simulated assistant interface.",
)
async def get_suggested_prompts() -> dict:
    """Return default starter prompts for the conversational interface."""
    return {
        "assistant_name": "ShipSafe Assistant",
        "notice": "Simulated Alexa+ experience for demonstration purposes only. Not connected to official Alexa services.",
        "suggested_prompts": [
            "Analyze my sample S3 configuration.",
            "What is the most serious issue?",
            "Explain why this configuration is risky.",
            "How can I fix the public-access issue?",
            "Show me the evidence.",
            "Analyze the corrected configuration.",
            "Did the fix resolve the original issue?",
            "Summarize the remaining risks.",
        ],
    }
