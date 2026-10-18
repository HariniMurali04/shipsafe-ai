"""Data models and enumerations for the ShipSafe AI Security Engine."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FindingType(str, Enum):
    """Categorization of engine analysis results."""

    CONFIRMED_RISK = "CONFIRMED_RISK"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    INFORMATIONAL = "INFORMATIONAL"


class Severity(str, Enum):
    """Risk severity classification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Confidence(str, Enum):
    """Confidence level of the security engine finding."""

    CERTAIN = "CERTAIN"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VerificationStatus(str, Enum):
    """Verification resolution status for a specific finding or rule."""

    RESOLVED = "Resolved"
    STILL_PRESENT = "Still present"
    UNABLE_TO_VERIFY = "Unable to verify"


class Finding(BaseModel):
    """Detailed model representing a single deterministic security finding."""

    finding_id: str = Field(..., description="Unique deterministic identifier for the finding")
    rule_id: str = Field(..., description="Identifier of the rule that generated the finding")
    finding_type: FindingType = Field(..., description="Classification: Confirmed risk, missing evidence, or informational")
    severity: Severity = Field(..., description="Assigned severity of the finding")
    title: str = Field(..., description="Short descriptive title of the finding")
    description: str = Field(..., description="Detailed explanation of the observed issue")
    evidence: Dict[str, Any] = Field(..., description="Concrete data extracted from the supplied input proving the issue")
    why_it_matters: str = Field(..., description="Explanation of security risk, impact, or blast radius")
    remediation: str = Field(..., description="Specific, actionable guidance to resolve the finding")
    confidence: Confidence = Field(..., description="Confidence level based on supplied evidence")


class VerificationItem(BaseModel):
    """Result of rechecking a specific finding or rule against a new configuration."""

    target_id: str = Field(..., description="Target finding ID or rule ID that was rechecked")
    rule_id: str = Field(..., description="Associated rule identifier")
    status: VerificationStatus = Field(..., description="Resolved, Still present, or Unable to verify")
    explanation: str = Field(..., description="Why the status was determined based on re-execution")
    evidence: Optional[Dict[str, Any]] = Field(default=None, description="Observed evidence from current configuration")


class AnalysisResponse(BaseModel):
    """Complete response payload for POST /api/analyze."""

    resource_id: str
    configuration_type: str
    evaluation_verdict: str = Field(
        ...,
        description="Overall verdict: RISKS_DETECTED, MISSING_EVIDENCE_DETECTED, or NO_EVALUATED_RISKS_DETECTED",
    )
    total_findings: int
    confirmed_risks_count: int
    missing_evidence_count: int
    informational_count: int
    findings: List[Finding]
    evaluated_rules: List[str]
    disclaimer: str = Field(
        ...,
        description="Important scope notice explaining that passing evaluated checks does not guarantee complete security",
    )


class VerificationResponse(BaseModel):
    """Complete response payload for POST /api/verify."""

    resource_id: str
    overall_verification_status: str = Field(
        ...,
        description="Summary status: ALL_RESOLVED, PARTIALLY_RESOLVED, UNRESOLVED, or NO_TARGETS_SPECIFIED",
    )
    total_rechecked: int
    resolved_count: int
    still_present_count: int
    unable_to_verify_count: int
    verification_results: List[VerificationItem]
    current_active_findings: List[Finding]
    disclaimer: str
