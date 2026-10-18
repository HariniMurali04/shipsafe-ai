"""Unit and integration tests for ShipSafe Assistant (Simulated Alexa+ Experience)."""

import os
from fastapi.testclient import TestClient
from app.assistant.models import AssistantChatRequest
from app.assistant.service import ShipSafeAssistantService
from app.main import app

client = TestClient(app)
assistant = ShipSafeAssistantService()


def test_assistant_welcome() -> None:
    """Test greeting / help command returns friendly welcome and starter prompts."""
    req = AssistantChatRequest(message="Hello assistant, what can you do?")
    res = assistant.handle_chat_message(req)

    assert res.intent == "welcome"
    assert "ShipSafe Assistant" in res.reply
    assert len(res.suggested_prompts) > 0
    assert "Simulated Alexa+" in res.notice


def test_assistant_analyze_sample_command() -> None:
    """Test 'Analyze my sample S3 configuration.' command."""
    req = AssistantChatRequest(message="Analyze my sample S3 configuration.")
    res = assistant.handle_chat_message(req)

    assert res.intent == "analyze_sample"
    assert "confirmed security risk" in res.reply
    assert res.agentic_step.startswith("Step 2")
    assert res.is_sample_data is True
    assert res.analysis_data is not None
    assert res.analysis_data.confirmed_risks_count > 0
    assert res.cards is not None
    assert len(res.cards) > 0


def test_assistant_most_serious_issue() -> None:
    """Test 'What is the most serious issue?' command."""
    req = AssistantChatRequest(message="What is the most serious issue?")
    res = assistant.handle_chat_message(req)

    assert res.intent == "most_serious_issue"
    assert "S3-PAB-001" in res.reply or "S3-POL-001" in res.reply
    assert res.cards is not None
    assert res.cards[0]["type"] == "finding_card"


def test_assistant_explain_risk() -> None:
    """Test 'Explain why this configuration is risky.' command."""
    req = AssistantChatRequest(message="Explain why this configuration is risky.")
    res = assistant.handle_chat_message(req)

    assert res.intent == "explain_risk"
    assert "confirmed security risks" in res.reply
    assert "not deployment-ready" in res.reply


def test_assistant_remediation_guidance() -> None:
    """Test 'How can I fix the public-access issue?' command."""
    req = AssistantChatRequest(message="How can I fix the public-access issue?")
    res = assistant.handle_chat_message(req)

    assert res.intent == "remediation_advice"
    assert "Public Access Block" in res.reply
    assert "aws:SecureTransport" in res.reply
    assert res.cards[0]["type"] == "remediation_recipe"


def test_assistant_show_evidence() -> None:
    """Test 'Show me the evidence.' command."""
    req = AssistantChatRequest(message="Show me the evidence.")
    res = assistant.handle_chat_message(req)

    assert res.intent == "show_evidence"
    assert "evidence" in res.reply.lower()
    assert res.cards[0]["type"] == "evidence_inspection"


def test_assistant_analyze_corrected() -> None:
    """Test 'Analyze the corrected configuration.' command."""
    req = AssistantChatRequest(message="Analyze the corrected configuration.")
    res = assistant.handle_chat_message(req)

    assert res.intent == "analyze_corrected"
    assert res.analysis_data is not None
    assert res.analysis_data.confirmed_risks_count == 0
    assert "Public access block and KMS encryption are now properly active" in res.reply


def test_assistant_verify_resolution() -> None:
    """Test 'Did the fix resolve the original issue?' command."""
    req = AssistantChatRequest(message="Did the fix resolve the original issue?")
    res = assistant.handle_chat_message(req)

    assert res.intent == "verify_resolution"
    assert res.verification_data is not None
    assert res.verification_data.overall_verification_status == "ALL_RESOLVED"
    assert "All" in res.reply and "Resolved" in res.reply
    assert res.cards[0]["type"] == "verification_card"


def test_assistant_summarize_remaining() -> None:
    """Test 'Summarize the remaining risks.' command."""
    req = AssistantChatRequest(message="Summarize the remaining risks.")
    res = assistant.handle_chat_message(req)

    assert res.intent == "summarize_remaining"
    assert "No remaining security risks were detected" in res.reply


def test_assistant_unsupported_command() -> None:
    """Test graceful handling of out-of-scope or unsupported user inputs."""
    req = AssistantChatRequest(message="Order a large pepperoni pizza to my AWS account")
    res = assistant.handle_chat_message(req)

    assert res.intent == "unsupported"
    assert "cannot fulfill the request" in res.reply
    assert "specializes in" in res.reply or "specialize in" in res.reply
    assert len(res.suggested_prompts) > 0


def test_assistant_missing_ai_key_deterministic_fallback(monkeypatch) -> None:
    """Ensure assistant works reliably with deterministic templates when no AI key is set."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    req = AssistantChatRequest(message="Explain why this configuration is risky.")
    res = assistant.handle_chat_message(req)

    assert res.explanation_mode == "deterministic_template"
    assert len(res.reply) > 20
    assert "confirmed security risks" in res.reply


def test_api_assistant_chat_endpoint() -> None:
    """Integration test for POST /api/assistant/chat."""
    response = client.post(
        "/api/assistant/chat",
        json={"message": "Analyze my sample S3 configuration."},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["intent"] == "analyze_sample"
    assert "confirmed_risks" in str(data["cards"])
    assert "Simulated Alexa+" in data["notice"]


def test_api_assistant_prompts_endpoint() -> None:
    """Integration test for GET /api/assistant/prompts."""
    response = client.get("/api/assistant/prompts")

    assert response.status_code == 200
    data = response.json()
    assert data["assistant_name"] == "ShipSafe Assistant"
    assert len(data["suggested_prompts"]) == 8
    assert "Analyze my sample S3 configuration." in data["suggested_prompts"]
