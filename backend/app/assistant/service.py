"""ShipSafe Assistant conversational service.

Implements the controlled 9-step agentic workflow for synthetic AWS S3 security analysis.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from app.assistant.explainer import (
    explain_conversational_response,
    generate_deterministic_finding_explanation,
    generate_deterministic_risk_summary,
    generate_deterministic_verification_summary,
)
from app.assistant.models import AssistantChatRequest, AssistantChatResponse
from app.engine.analyzer import analyze_s3_configuration, verify_s3_configuration
from app.engine.models import AnalysisResponse, Finding, VerificationResponse

SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "samples"


def load_sample_file(filename: str) -> Dict[str, Any]:
    """Safely load a synthetic sample JSON file."""
    path = SAMPLES_DIR / filename
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


class ShipSafeAssistantService:
    """Conversational assistant service powering the Simulated Alexa+ experience."""

    def __init__(self) -> None:
        self.insecure_sample = load_sample_file("insecure_s3_config.json")
        self.secure_sample = load_sample_file("secure_s3_config.json")

    def handle_chat_message(self, request: AssistantChatRequest) -> AssistantChatResponse:
        """Route user's typed message to the appropriate workflow handler."""
        msg = request.message.strip().lower()

        # Step 1 & 2: Analyze sample / custom configuration
        if any(keyword in msg for keyword in ["analyze my sample", "analyze sample", "run analysis", "scan sample", "check configuration"]):
            return self._handle_analyze_sample(request)

        # Step 3: Most serious issue
        elif any(keyword in msg for keyword in ["most serious", "biggest risk", "top issue", "worst problem", "highest severity"]):
            return self._handle_most_serious_issue(request)

        # Step 4: Explain why configuration is risky
        elif any(keyword in msg for keyword in ["explain why", "why is this risky", "explain the risk", "what could happen", "impact"]):
            return self._handle_explain_risk(request)

        # Step 5: How can I fix the public-access issue / remediation
        elif any(keyword in msg for keyword in ["how can i fix", "how to fix", "remediation", "how do i fix"]):
            return self._handle_remediation_guidance(request)

        # Step 4b: Show evidence
        elif any(keyword in msg for keyword in ["show me the evidence", "show evidence", "what evidence", "proof"]):
            return self._handle_show_evidence(request)

        # Step 6 & 7: Analyze corrected configuration
        elif any(keyword in msg for keyword in ["analyze the corrected", "analyze corrected", "check the secure", "test secure"]):
            return self._handle_analyze_corrected(request)

        # Step 8 & 9: Did the fix resolve the original issue?
        elif any(keyword in msg for keyword in ["did the fix resolve", "did it fix", "resolve the original", "verify fix", "verify remediation"]):
            return self._handle_verify_resolution(request)

        # Step 9b: Summarize remaining risks
        elif any(keyword in msg for keyword in ["summarize the remaining", "remaining risk", "what risks are left", "what issues remain"]):
            return self._handle_summarize_remaining(request)

        # Help / Capabilities greeting
        elif any(keyword in msg for keyword in ["help", "what can you do", "commands", "hello", "hi"]):
            return self._handle_welcome_help()

        # Graceful fallback for unsupported requests
        else:
            return self._handle_unsupported_request(request.message)

    def _get_active_analysis(self, request: AssistantChatRequest) -> AnalysisResponse:
        """Retrieve or compute analysis for current configuration."""
        config = request.current_config or self.insecure_sample
        return analyze_s3_configuration(config)

    def _handle_analyze_sample(self, request: AssistantChatRequest) -> AssistantChatResponse:
        """Step 1 & 2: Inspect supplied config and run deterministic security checks."""
        config = request.current_config or self.insecure_sample
        analysis = analyze_s3_configuration(config)

        reply = (
            f"I have inspected synthetic configuration '{analysis.resource_id}' and executed the deterministic "
            f"security rule engine. I identified {analysis.confirmed_risks_count} confirmed security risk(s), "
            f"{analysis.missing_evidence_count} missing evidence gap(s), and {analysis.informational_count} "
            f"informational observation(s). Would you like to review the most serious issue?"
        )

        cards = [
            {
                "type": "summary_card",
                "resource_id": analysis.resource_id,
                "verdict": analysis.evaluation_verdict,
                "confirmed_risks": analysis.confirmed_risks_count,
                "missing_evidence": analysis.missing_evidence_count,
                "informational": analysis.informational_count,
                "top_finding": analysis.findings[0].model_dump() if analysis.findings else None,
            }
        ]

        return AssistantChatResponse(
            reply=reply,
            intent="analyze_sample",
            agentic_step="Step 2: Deterministic security checks executed",
            explanation_mode="deterministic_template",
            is_sample_data=True,
            cards=cards,
            suggested_prompts=[
                "What is the most serious issue?",
                "Explain why this configuration is risky.",
                "Show me the evidence.",
                "How can I fix the public-access issue?",
            ],
            analysis_data=analysis,
        )

    def _handle_most_serious_issue(self, request: AssistantChatRequest) -> AssistantChatResponse:
        """Step 3: Summarize the most important finding."""
        analysis = self._get_active_analysis(request)
        confirmed = [f for f in analysis.findings if f.finding_type.value == "CONFIRMED_RISK"]

        if not confirmed:
            return AssistantChatResponse(
                reply="No confirmed critical risks were identified in the current configuration.",
                intent="most_serious_issue",
                agentic_step="Step 3: Finding prioritization complete",
                explanation_mode="deterministic_template",
                is_sample_data=True,
                suggested_prompts=["Analyze my sample S3 configuration."],
            )

        top = confirmed[0]
        reply, mode = explain_conversational_response("most_serious_issue", {"target_finding": top})

        cards = [{"type": "finding_card", "finding": top.model_dump()}]

        return AssistantChatResponse(
            reply=reply,
            intent="most_serious_issue",
            agentic_step="Step 3: Most critical vulnerability isolated",
            explanation_mode=mode,
            is_sample_data=True,
            cards=cards,
            suggested_prompts=[
                "Show me the evidence.",
                "How can I fix the public-access issue?",
                "Analyze the corrected configuration.",
            ],
            analysis_data=analysis,
        )

    def _handle_explain_risk(self, request: AssistantChatRequest) -> AssistantChatResponse:
        """Step 4: Explain evidence and possible architectural impact."""
        analysis = self._get_active_analysis(request)
        reply, mode = explain_conversational_response("explain_risk", {"analysis": analysis})

        cards = [
            {
                "type": "risk_breakdown",
                "resource_id": analysis.resource_id,
                "confirmed_risks": analysis.confirmed_risks_count,
                "critical_rules": [f.rule_id for f in analysis.findings if f.severity.value in ("CRITICAL", "HIGH")],
            }
        ]

        return AssistantChatResponse(
            reply=reply,
            intent="explain_risk",
            agentic_step="Step 4: Evidence and architectural blast radius explained",
            explanation_mode=mode,
            is_sample_data=True,
            cards=cards,
            suggested_prompts=[
                "How can I fix the public-access issue?",
                "Show me the evidence.",
                "Analyze the corrected configuration.",
            ],
            analysis_data=analysis,
        )

    def _handle_remediation_guidance(self, request: AssistantChatRequest) -> AssistantChatResponse:
        """Step 5: Suggest actionable remediation."""
        analysis = self._get_active_analysis(request)
        pab_finding = next((f for f in analysis.findings if f.rule_id == "S3-PAB-001"), None)
        pol_finding = next((f for f in analysis.findings if f.rule_id == "S3-POL-001"), None)

        reply = (
            "To fix public access on this S3 bucket, take two key actions: First, enable all 4 Public Access Block "
            "flags (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets). Second, "
            "remove the wildcard Principal '*' from your bucket policy, and add a Deny statement enforcing "
            "aws:SecureTransport: false for HTTPS requests. Would you like me to analyze the corrected configuration?"
        )

        cards = [
            {
                "type": "remediation_recipe",
                "title": "Remediation Recipe: S3 Public Access Prevention",
                "steps": [
                    "Set configurations.public_access_block all four flags to true",
                    "Remove wildcard Principal '*' from configurations.bucket_policy",
                    "Add Deny statement where aws:SecureTransport is false",
                    "Ensure access_control_list.grants does not contain AllUsers",
                ],
                "sample_reference": "samples/secure_s3_config.json",
            }
        ]

        return AssistantChatResponse(
            reply=reply,
            intent="remediation_advice",
            agentic_step="Step 5: Remediation recipe generated",
            explanation_mode="deterministic_template",
            is_sample_data=True,
            cards=cards,
            suggested_prompts=[
                "Analyze the corrected configuration.",
                "Did the fix resolve the original issue?",
                "Show me the evidence.",
            ],
            analysis_data=analysis,
        )

    def _handle_show_evidence(self, request: AssistantChatRequest) -> AssistantChatResponse:
        """Step 4b: Provide concrete extracted evidence."""
        analysis = self._get_active_analysis(request)
        top = analysis.findings[0] if analysis.findings else None

        if not top:
            return AssistantChatResponse(
                reply="No active findings with evidence are currently available.",
                intent="show_evidence",
                agentic_step="Step 4: Evidence inspection",
                explanation_mode="deterministic_template",
                is_sample_data=True,
            )

        reply, mode = explain_conversational_response("evidence", {"target_finding": top})

        cards = [
            {
                "type": "evidence_inspection",
                "finding_id": top.finding_id,
                "rule_id": top.rule_id,
                "evidence_payload": top.evidence,
            }
        ]

        return AssistantChatResponse(
            reply=reply,
            intent="show_evidence",
            agentic_step="Step 4: Concrete evidence presented",
            explanation_mode=mode,
            is_sample_data=True,
            cards=cards,
            suggested_prompts=[
                "How can I fix the public-access issue?",
                "Analyze the corrected configuration.",
                "Did the fix resolve the original issue?",
            ],
            analysis_data=analysis,
        )

    def _handle_analyze_corrected(self, request: AssistantChatRequest) -> AssistantChatResponse:
        """Step 6 & 7: Let user provide or load corrected config and rerun checks."""
        config = request.corrected_config or self.secure_sample
        analysis = analyze_s3_configuration(config)

        reply = (
            f"I ran the security checks against the corrected configuration '{analysis.resource_id}'. "
            f"The engine found {analysis.confirmed_risks_count} confirmed risks and {analysis.missing_evidence_count} "
            f"missing evidence items. Public access block and KMS encryption are now properly active! "
            f"Would you like to verify whether this resolved the original issues?"
        )

        cards = [
            {
                "type": "summary_card",
                "resource_id": analysis.resource_id,
                "verdict": analysis.evaluation_verdict,
                "confirmed_risks": analysis.confirmed_risks_count,
                "missing_evidence": analysis.missing_evidence_count,
                "informational": analysis.informational_count,
            }
        ]

        return AssistantChatResponse(
            reply=reply,
            intent="analyze_corrected",
            agentic_step="Step 7: Checks re-executed on corrected configuration",
            explanation_mode="deterministic_template",
            is_sample_data=True,
            cards=cards,
            suggested_prompts=[
                "Did the fix resolve the original issue?",
                "Summarize the remaining risks.",
            ],
            analysis_data=analysis,
        )

    def _handle_verify_resolution(self, request: AssistantChatRequest) -> AssistantChatResponse:
        """Step 8 & 9: Compare original findings and summarize verification result."""
        config = request.corrected_config or self.secure_sample
        targets = request.active_finding_ids or ["S3-PAB-001", "S3-POL-001", "S3-ACL-001", "S3-ENC-001"]

        verification = verify_s3_configuration(config, target_rule_ids=targets)
        reply, mode = explain_conversational_response("verify_resolution", {"verification": verification})

        cards = [
            {
                "type": "verification_card",
                "overall_status": verification.overall_verification_status,
                "resolved_count": verification.resolved_count,
                "still_present_count": verification.still_present_count,
                "items": [item.model_dump() for item in verification.verification_results],
            }
        ]

        return AssistantChatResponse(
            reply=reply,
            intent="verify_resolution",
            agentic_step="Step 9: Verification resolution synthesized",
            explanation_mode=mode,
            is_sample_data=True,
            cards=cards,
            suggested_prompts=[
                "Summarize the remaining risks.",
                "Analyze my sample S3 configuration.",
            ],
            verification_data=verification,
        )

    def _handle_summarize_remaining(self, request: AssistantChatRequest) -> AssistantChatResponse:
        """Step 9b: Summarize any remaining risks."""
        config = request.corrected_config or self.secure_sample
        analysis = analyze_s3_configuration(config)

        if analysis.confirmed_risks_count == 0:
            reply = (
                f"No remaining security risks were detected in '{analysis.resource_id}'. "
                f"All evaluated high and critical vulnerabilities are resolved. Keep in mind that static checks "
                f"evaluate synthetic declared parameters and do not account for external IAM policies."
            )
        else:
            reply = (
                f"There are {analysis.confirmed_risks_count} residual confirmed risk(s) in the configuration. "
                f"Review the remaining findings to achieve a clean baseline."
            )

        return AssistantChatResponse(
            reply=reply,
            intent="summarize_remaining",
            agentic_step="Step 9: Remaining risk posture summarized",
            explanation_mode="deterministic_template",
            is_sample_data=True,
            suggested_prompts=[
                "Analyze my sample S3 configuration.",
                "What is the most serious issue?",
            ],
            analysis_data=analysis,
        )

    def _handle_welcome_help(self) -> AssistantChatResponse:
        """Return welcome guidance and example commands."""
        reply = (
            "Hello! I am ShipSafe Assistant &mdash; your simulated Alexa+ cloud security advisor. "
            "I can analyze synthetic AWS S3 configurations, explain vulnerabilities, provide remediation advice, "
            "and verify fixes before deployment. What would you like to do?"
        )
        return AssistantChatResponse(
            reply=reply,
            intent="welcome",
            agentic_step="Step 1: Session initialized",
            explanation_mode="deterministic_template",
            is_sample_data=True,
            suggested_prompts=[
                "Analyze my sample S3 configuration.",
                "What is the most serious issue?",
                "Explain why this configuration is risky.",
                "How can I fix the public-access issue?",
            ],
        )

    def _handle_unsupported_request(self, original_message: str) -> AssistantChatResponse:
        """Gracefully handle queries outside static S3 security analysis."""
        reply = (
            f"I cannot fulfill the request '{original_message}'. As ShipSafe Assistant, I specialize in analyzing, "
            f"explaining, and verifying AWS S3 configurations against deterministic security baselines. "
            f"I do not connect to live AWS accounts or modify cloud resources. Try one of the supported queries below:"
        )
        return AssistantChatResponse(
            reply=reply,
            intent="unsupported",
            agentic_step="Controlled Boundary",
            explanation_mode="deterministic_template",
            is_sample_data=True,
            suggested_prompts=[
                "Analyze my sample S3 configuration.",
                "What is the most serious issue?",
                "Explain why this configuration is risky.",
                "How can I fix the public-access issue?",
                "Analyze the corrected configuration.",
            ],
        )
