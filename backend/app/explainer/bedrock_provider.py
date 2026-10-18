"""Optional Amazon Bedrock explanation provider for ShipSafe AI.

Uses official AWS SDK (boto3) to invoke Bedrock models when explicitly enabled by environment variables.
Never hardcodes AWS credentials or secret keys.
Never logs sensitive keys or tokens.
Fails safely and transparently to deterministic fallback.
"""

import json
import logging
import os
from typing import Any, Dict, Optional

from app.engine.models import AnalysisResponse, Finding
from app.explainer.provider import BaseExplanationProvider, ExplanationResult

logger = logging.getLogger("shipsafe.explainer.bedrock")

SYSTEM_PROMPT = (
    "You are ShipSafe AI, an expert cloud security advisor explaining static configuration findings.\n"
    "CRITICAL CONSTRAINTS:\n"
    "1. Explain ONLY the provided findings and their concrete evidence.\n"
    "2. Do NOT invent new findings or speculate on unprovided settings.\n"
    "3. Do NOT change assigned severity levels.\n"
    "4. Do NOT claim any finding is resolved.\n"
    "5. Clearly identify any uncertainty if evidence is partial.\n"
    "6. Do NOT recommend executing commands against live production AWS accounts without review.\n"
    "Keep explanations concise, actionable, and developer-friendly."
)


class BedrockInvocationError(Exception):
    """Raised when an Amazon Bedrock invocation fails."""

    def __init__(self, message: str, error_code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "BEDROCK_ERROR"


class AmazonBedrockExplanationProvider(BaseExplanationProvider):
    """Provider for generating explanations using Amazon Bedrock foundation models."""

    def __init__(self) -> None:
        self.enabled = os.getenv("BEDROCK_ENABLED", "false").lower() in ("true", "1", "yes")
        self.region = os.getenv("BEDROCK_REGION") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
        self.model_id = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
        self.max_tokens = int(os.getenv("BEDROCK_MAX_TOKENS", "400"))
        self.temperature = float(os.getenv("BEDROCK_TEMPERATURE", "0.0"))
        self.timeout_seconds = float(os.getenv("BEDROCK_TIMEOUT_SECONDS", "5.0"))

        self._client: Any = None

    @property
    def name(self) -> str:
        return "amazon_bedrock"

    @property
    def is_available(self) -> bool:
        """Check if Bedrock is explicitly enabled and boto3 is installed."""
        if not self.enabled:
            return False
        try:
            import boto3
            return True
        except ImportError:
            return False

    def _get_client(self) -> Any:
        """Initialize Bedrock runtime client without logging credentials."""
        if self._client is not None:
            return self._client

        import boto3
        from botocore.config import Config

        # Configure reasonable timeouts to prevent application hangs
        boto_config = Config(
            region_name=self.region,
            connect_timeout=self.timeout_seconds,
            read_timeout=self.timeout_seconds,
            retries={"max_attempts": 1, "mode": "standard"},
        )

        # boto3 automatically inspects standard AWS environment variables, profiles, and IAM roles
        self._client = boto3.client("bedrock-runtime", config=boto_config)
        return self._client

    def explain_finding(self, finding: Finding) -> ExplanationResult:
        """Explain an individual security finding using Bedrock."""
        prompt = (
            f"Explain this security finding to a developer:\n\n"
            f"Title: {finding.title}\n"
            f"Rule ID: {finding.rule_id}\n"
            f"Severity: {finding.severity.value}\n"
            f"Finding Type: {finding.finding_type.value}\n"
            f"Concrete Evidence Extracted: {json.dumps(finding.evidence)}\n"
            f"Why It Matters: {finding.why_it_matters}\n"
            f"Remediation Guidance: {finding.remediation}\n"
        )

        explanation = self._invoke_model(prompt)
        return ExplanationResult(
            explanation=explanation,
            provider_used="amazon_bedrock",
            is_fallback=False,
            disclaimer="AI explanation generated via Amazon Bedrock based strictly on evaluated static findings.",
        )

    def explain_analysis_posture(self, analysis: AnalysisResponse) -> ExplanationResult:
        """Explain the overall architectural posture using Bedrock."""
        findings_summary = [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "evidence": f.evidence,
            }
            for f in analysis.findings
        ]

        prompt = (
            f"Summarize the security posture for this synthetic configuration:\n\n"
            f"Resource ID: {analysis.resource_id}\n"
            f"Configuration Type: {analysis.configuration_type}\n"
            f"Verdict: {analysis.evaluation_verdict}\n"
            f"Confirmed Risks: {analysis.confirmed_risks_count}\n"
            f"Missing Evidence: {analysis.missing_evidence_count}\n"
            f"Findings: {json.dumps(findings_summary)}\n"
        )

        explanation = self._invoke_model(prompt)
        return ExplanationResult(
            explanation=explanation,
            provider_used="amazon_bedrock",
            is_fallback=False,
            disclaimer="AI posture explanation generated via Amazon Bedrock based strictly on evaluated static findings.",
        )

    def _invoke_model(self, user_prompt: str) -> str:
        """Execute Bedrock API call with robust error handling and sanitized logging."""
        client = self._get_client()

        # Build model-specific request body
        if "claude" in self.model_id.lower():
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_prompt}],
            }
        elif "titan" in self.model_id.lower():
            body = {
                "inputText": f"{SYSTEM_PROMPT}\n\nUser: {user_prompt}\n\nAssistant:",
                "textGenerationConfig": {
                    "maxTokenCount": self.max_tokens,
                    "temperature": self.temperature,
                },
            }
        else:
            # Generic fallback payload format
            body = {
                "prompt": f"{SYSTEM_PROMPT}\n\nUser: {user_prompt}\n\nAssistant:",
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
            }

        try:
            response = client.invoke_model(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(body),
            )

            response_body = json.loads(response["body"].read().decode("utf-8"))

            # Parse model output
            if "claude" in self.model_id.lower():
                content_blocks = response_body.get("content", [])
                if content_blocks and isinstance(content_blocks, list):
                    return str(content_blocks[0].get("text", "")).strip()
            elif "titan" in self.model_id.lower():
                results = response_body.get("results", [])
                if results and isinstance(results, list):
                    return str(results[0].get("outputText", "")).strip()

            # Generic fallback extractor
            return str(response_body.get("completion") or response_body.get("text") or "").strip()

        except Exception as e:
            # SANITIZATION: Never log secrets, credentials, or session tokens
            resp = getattr(e, "response", None)
            error_code = None
            if isinstance(resp, dict):
                error_code = resp.get("Error", {}).get("Code")
            if not error_code:
                error_code = type(e).__name__

            sanitized_msg = f"Bedrock invocation failed ({error_code})."
            logger.warning(sanitized_msg)
            raise BedrockInvocationError(sanitized_msg, error_code=error_code) from e
