"""Core analysis and verification engine for ShipSafe AI."""

from typing import Any, Dict, List, Optional
from app.engine.models import (
    AnalysisResponse,
    Finding,
    FindingType,
    Severity,
    VerificationItem,
    VerificationResponse,
    VerificationStatus,
)
from app.engine.rules import (
    ALL_EVALUATED_RULE_IDS,
    check_access_control_list,
    check_bucket_policy,
    check_public_access_block,
    check_server_access_logging,
    check_server_side_encryption,
    check_unsupported_fields,
    check_versioning,
)
from app.engine.validator import validate_s3_configuration_payload

SECURITY_SCOPE_DISCLAIMER = (
    "ShipSafe AI security analysis is strictly scoped to evaluated static synthetic rules for "
    "AWS S3 bucket configurations. Passing these checks confirms that no known evaluated risks "
    "were detected in the supplied configuration, but does not guarantee complete security of "
    "the broader cloud infrastructure. External controls including IAM policies, organization SCPs, "
    "KMS key policies, and VPC endpoints must also be evaluated."
)

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


def analyze_s3_configuration(payload: Any) -> AnalysisResponse:
    """Analyze a synthetic S3 bucket configuration and return deterministic findings.

    Args:
        payload: JSON object representing the S3 bucket configuration.

    Returns:
        AnalysisResponse with categorized findings, counts, and evaluation scope.
    """
    normalized_config, resource_id = validate_s3_configuration_payload(payload)
    configurations = normalized_config.get("configurations", {})

    findings: List[Finding] = []

    # Execute all deterministic security checks
    findings.extend(check_public_access_block(configurations, resource_id))
    findings.extend(check_bucket_policy(configurations, resource_id))
    findings.extend(check_access_control_list(configurations, resource_id))
    findings.extend(check_server_side_encryption(configurations, resource_id))
    findings.extend(check_server_access_logging(configurations, resource_id))
    findings.extend(check_versioning(configurations, resource_id))
    findings.extend(check_unsupported_fields(configurations, resource_id))

    # Sort deterministically by severity rank, rule_id, then finding_id
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule_id, f.finding_id))

    # Categorize findings
    confirmed_risks = [f for f in findings if f.finding_type == FindingType.CONFIRMED_RISK]
    missing_evidence = [f for f in findings if f.finding_type == FindingType.MISSING_EVIDENCE]
    informational = [f for f in findings if f.finding_type == FindingType.INFORMATIONAL]

    if confirmed_risks:
        verdict = "RISKS_DETECTED"
    elif missing_evidence:
        verdict = "NEEDS_EVIDENCE"
    else:
        verdict = "NO_EVALUATED_RISKS_DETECTED"

    return AnalysisResponse(
        resource_id=resource_id,
        configuration_type=str(normalized_config.get("configuration_type")),
        evaluation_verdict=verdict,
        total_findings=len(findings),
        confirmed_risks_count=len(confirmed_risks),
        missing_evidence_count=len(missing_evidence),
        informational_count=len(informational),
        findings=findings,
        evaluated_rules=ALL_EVALUATED_RULE_IDS,
        disclaimer=SECURITY_SCOPE_DISCLAIMER,
    )


def verify_s3_configuration(
    payload: Any,
    target_finding_ids: Optional[List[str]] = None,
    target_rule_ids: Optional[List[str]] = None,
) -> VerificationResponse:
    """Rerun the analysis engine against the updated configuration to verify remediation.

    Args:
        payload: The updated S3 configuration to evaluate.
        target_finding_ids: Optional list of finding IDs to recheck.
        target_rule_ids: Optional list of rule IDs to recheck.

    Returns:
        VerificationResponse with per-target status ('Resolved', 'Still present', or 'Unable to verify').
    """
    # Rerun the analysis engine fresh on the new configuration (no simulated success)
    current_analysis = analyze_s3_configuration(payload)
    active_findings = current_analysis.findings
    active_rule_map: Dict[str, List[Finding]] = {}
    active_finding_id_set = set()

    for f in active_findings:
        active_finding_id_set.add(f.finding_id)
        active_rule_map.setdefault(f.rule_id, []).append(f)

    # Collect unique targets to verify
    targets_to_check: List[Dict[str, str]] = []

    if target_finding_ids:
        for fid in target_finding_ids:
            rule_id_part = fid.split(":")[0] if ":" in fid else fid
            targets_to_check.append({"target_id": fid, "rule_id": rule_id_part})

    if target_rule_ids:
        for rid in target_rule_ids:
            targets_to_check.append({"target_id": rid, "rule_id": rid})

    # If no targets were specified, recheck all rules that have active findings or all evaluated rules
    if not targets_to_check:
        for rid in ALL_EVALUATED_RULE_IDS:
            targets_to_check.append({"target_id": rid, "rule_id": rid})

    verification_items: List[VerificationItem] = []
    resolved_count = 0
    still_present_count = 0
    unable_to_verify_count = 0

    known_rule_ids = set(ALL_EVALUATED_RULE_IDS)

    for target in targets_to_check:
        tid = target["target_id"]
        rid = target["rule_id"]

        # Check if the rule is part of our known evaluation catalog
        if rid not in known_rule_ids and tid not in active_finding_id_set:
            verification_items.append(
                VerificationItem(
                    target_id=tid,
                    rule_id=rid,
                    status=VerificationStatus.UNABLE_TO_VERIFY,
                    explanation=f"Target '{tid}' does not match any recognized rule ID in the ShipSafe AI engine.",
                    evidence=None,
                )
            )
            unable_to_verify_count += 1
            continue

        # Check if this specific finding ID or rule is still active in current analysis
        matching_findings = active_rule_map.get(rid, [])
        is_still_present = (tid in active_finding_id_set) or (len(matching_findings) > 0)

        if is_still_present:
            sample_evidence = matching_findings[0].evidence if matching_findings else None
            verification_items.append(
                VerificationItem(
                    target_id=tid,
                    rule_id=rid,
                    status=VerificationStatus.STILL_PRESENT,
                    explanation=(
                        f"Rule '{rid}' still triggers on the updated configuration with "
                        f"{len(matching_findings)} active finding(s)."
                    ),
                    evidence=sample_evidence,
                )
            )
            still_present_count += 1
        else:
            verification_items.append(
                VerificationItem(
                    target_id=tid,
                    rule_id=rid,
                    status=VerificationStatus.RESOLVED,
                    explanation=f"Rule '{rid}' was re-evaluated against the updated configuration and no longer triggers.",
                    evidence=None,
                )
            )
            resolved_count += 1

    # Determine overall status
    if len(verification_items) == 0:
        overall_status = "NO_TARGETS_SPECIFIED"
    elif resolved_count == len(verification_items):
        overall_status = "ALL_RESOLVED"
    elif resolved_count > 0 and still_present_count > 0:
        overall_status = "PARTIALLY_RESOLVED"
    else:
        overall_status = "UNRESOLVED"

    return VerificationResponse(
        resource_id=current_analysis.resource_id,
        overall_verification_status=overall_status,
        total_rechecked=len(verification_items),
        resolved_count=resolved_count,
        still_present_count=still_present_count,
        unable_to_verify_count=unable_to_verify_count,
        verification_results=verification_items,
        current_active_findings=active_findings,
        disclaimer=SECURITY_SCOPE_DISCLAIMER,
    )
