"""Deterministic security rules for synthetic AWS S3 configurations."""

from typing import Any, Dict, List, Set
from app.engine.models import Confidence, Finding, FindingType, Severity

KNOWN_S3_CONFIG_FIELDS: Set[str] = {
    "public_access_block",
    "access_control_list",
    "server_side_encryption",
    "versioning",
    "server_access_logging",
    "bucket_policy",
    "object_lock",
    "lifecycle_rules",
    "cors",
    "tags",
}

ALL_EVALUATED_RULE_IDS: List[str] = [
    "S3-PAB-001",
    "S3-PAB-MISSING",
    "S3-POL-001",
    "S3-POL-002",
    "S3-ACL-001",
    "S3-ENC-001",
    "S3-ENC-MISSING",
    "S3-ENC-INFO",
    "S3-LOG-001",
    "S3-LOG-MISSING",
    "S3-LOG-INFO",
    "S3-VER-001",
    "S3-VER-MISSING",
    "S3-CFG-UNSUPPORTED",
]


def check_public_access_block(configurations: Dict[str, Any], resource_id: str) -> List[Finding]:
    """Check S3 Public Access Block settings."""
    findings: List[Finding] = []

    if "public_access_block" not in configurations or configurations["public_access_block"] is None:
        findings.append(
            Finding(
                finding_id=f"S3-PAB-MISSING:{resource_id}",
                rule_id="S3-PAB-MISSING",
                finding_type=FindingType.MISSING_EVIDENCE,
                severity=Severity.HIGH,
                title="Public Access Block Configuration Omitted",
                description="The configuration does not specify a public_access_block configuration block.",
                evidence={
                    "field_path": "configurations.public_access_block",
                    "observed": "null or missing",
                },
                why_it_matters=(
                    "Without explicit Public Access Block settings, the bucket may rely on default account "
                    "or bucket ACL behaviors, increasing the likelihood of unintended exposure."
                ),
                remediation=(
                    "Define configurations.public_access_block with all 4 settings "
                    "(block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) set to true."
                ),
                confidence=Confidence.CERTAIN,
            )
        )
        return findings

    pab = configurations["public_access_block"]
    if not isinstance(pab, dict):
        return findings

    required_flags = [
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets",
    ]
    disabled_flags = [flag for flag in required_flags if pab.get(flag) is not True]

    if disabled_flags:
        observed_flags = {flag: pab.get(flag) for flag in required_flags}
        findings.append(
            Finding(
                finding_id=f"S3-PAB-001:{resource_id}",
                rule_id="S3-PAB-001",
                finding_type=FindingType.CONFIRMED_RISK,
                severity=Severity.CRITICAL,
                title="S3 Public Access Block Protection Disabled",
                description=(
                    f"Public Access Block has {len(disabled_flags)} disabled or non-boolean protection flag(s): "
                    f"{', '.join(disabled_flags)}."
                ),
                evidence={
                    "field_path": "configurations.public_access_block",
                    "disabled_flags": disabled_flags,
                    "observed_settings": observed_flags,
                },
                why_it_matters=(
                    "AWS S3 Public Access Block is the primary defense layer preventing public exposure. "
                    "Disabling these flags permits buckets to accept public policies and ACLs."
                ),
                remediation=(
                    "Enable all four Public Access Block settings by setting block_public_acls, "
                    "ignore_public_acls, block_public_policy, and restrict_public_buckets to true."
                ),
                confidence=Confidence.CERTAIN,
            )
        )

    return findings


def check_bucket_policy(configurations: Dict[str, Any], resource_id: str) -> List[Finding]:
    """Check S3 bucket policy for public access grants and TLS enforcement."""
    findings: List[Finding] = []

    if "bucket_policy" not in configurations or configurations["bucket_policy"] is None:
        return findings

    policy = configurations["bucket_policy"]
    if not isinstance(policy, dict):
        return findings

    statements = policy.get("statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return findings

    has_tls_enforcement = False

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue

        sid = stmt.get("sid", f"Statement_{idx}")
        effect = stmt.get("effect", "")
        principal = stmt.get("principal")
        action = stmt.get("action", [])
        condition = stmt.get("condition")

        # Check for public read/write grants
        is_wildcard_principal = False
        if principal == "*":
            is_wildcard_principal = True
        elif isinstance(principal, dict) and principal.get("AWS") == "*":
            is_wildcard_principal = True
        elif isinstance(principal, list) and "*" in principal:
            is_wildcard_principal = True

        if effect.lower() == "allow" and is_wildcard_principal:
            # Check if there is a mitigating restriction condition
            has_condition = bool(condition and isinstance(condition, dict) and len(condition) > 0)
            if not has_condition:
                findings.append(
                    Finding(
                        finding_id=f"S3-POL-001:{resource_id}:{sid}",
                        rule_id="S3-POL-001",
                        finding_type=FindingType.CONFIRMED_RISK,
                        severity=Severity.CRITICAL,
                        title=f"Bucket Policy Grants Public Access ({sid})",
                        description=(
                            f"Statement '{sid}' allows unauthenticated public access (Principal: '*') "
                            f"without restrictive conditions."
                        ),
                        evidence={
                            "field_path": f"configurations.bucket_policy.statement[{idx}]",
                            "sid": sid,
                            "effect": effect,
                            "principal": principal,
                            "action": action,
                            "has_condition": False,
                        },
                        why_it_matters=(
                            "Publicly accessible bucket policies allow anyone on the internet to read, "
                            "download, or modify bucket contents, causing catastrophic data exposure."
                        ),
                        remediation=(
                            "Remove public wildcard principal '*' or restrict the statement to authenticated IAM ARNs "
                            "with specific condition constraints."
                        ),
                        confidence=Confidence.CERTAIN,
                    )
                )

        # Check for TLS / HTTPS enforcement
        # e.g., Deny where aws:SecureTransport == false
        if effect.lower() == "deny" and isinstance(condition, dict):
            bool_cond = condition.get("Bool") or condition.get("bool")
            if isinstance(bool_cond, dict):
                secure_transport = bool_cond.get("aws:SecureTransport")
                if secure_transport in (False, "false", "False"):
                    has_tls_enforcement = True

    if not has_tls_enforcement:
        findings.append(
            Finding(
                finding_id=f"S3-POL-002:{resource_id}",
                rule_id="S3-POL-002",
                finding_type=FindingType.CONFIRMED_RISK,
                severity=Severity.MEDIUM,
                title="Bucket Policy Missing TLS Enforcement",
                description="The bucket policy does not explicitly deny non-HTTPS (unencrypted in transit) requests.",
                evidence={
                    "field_path": "configurations.bucket_policy",
                    "tls_deny_statement_present": False,
                },
                why_it_matters=(
                    "Without TLS enforcement, data in transit between clients and S3 can be intercepted or "
                    "altered via man-in-the-middle (MITM) attacks over plaintext HTTP."
                ),
                remediation=(
                    "Add a statement with Effect: Deny, Principal: '*', Action: 's3:*', and Condition: "
                    "{'Bool': {'aws:SecureTransport': 'false'}}."
                ),
                confidence=Confidence.HIGH,
            )
        )

    return findings


def check_access_control_list(configurations: Dict[str, Any], resource_id: str) -> List[Finding]:
    """Check S3 Access Control List (ACL) for public grants."""
    findings: List[Finding] = []

    if "access_control_list" not in configurations or configurations["access_control_list"] is None:
        return findings

    acl = configurations["access_control_list"]
    if not isinstance(acl, dict):
        return findings

    grants = acl.get("grants", [])
    if not isinstance(grants, list):
        return findings

    public_groups = {
        "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers (Public Internet)",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers (Any AWS Account)",
    }

    detected_public_grants = []
    for grant in grants:
        if not isinstance(grant, dict):
            continue
        grantee = grant.get("grantee", {})
        if isinstance(grantee, dict):
            uri = grantee.get("uri", "")
            if uri in public_groups:
                detected_public_grants.append(
                    {
                        "target_group": public_groups[uri],
                        "uri": uri,
                        "permission": grant.get("permission", "UNKNOWN"),
                    }
                )

    if detected_public_grants:
        findings.append(
            Finding(
                finding_id=f"S3-ACL-001:{resource_id}",
                rule_id="S3-ACL-001",
                finding_type=FindingType.CONFIRMED_RISK,
                severity=Severity.HIGH,
                title="S3 Bucket ACL Grants Public or Global Access",
                description="The Access Control List contains grants permitting public or global AWS users.",
                evidence={
                    "field_path": "configurations.access_control_list.grants",
                    "detected_public_grants": detected_public_grants,
                },
                why_it_matters=(
                    "ACL grants to AllUsers or AuthenticatedUsers bypass identity boundaries and expose objects "
                    "to arbitrary third parties."
                ),
                remediation="Remove public grantee entries from access_control_list.grants or disable ACLs entirely.",
                confidence=Confidence.CERTAIN,
            )
        )

    return findings


def check_server_side_encryption(configurations: Dict[str, Any], resource_id: str) -> List[Finding]:
    """Check Server-Side Encryption (SSE) configuration."""
    findings: List[Finding] = []

    if "server_side_encryption" not in configurations or configurations["server_side_encryption"] is None:
        findings.append(
            Finding(
                finding_id=f"S3-ENC-MISSING:{resource_id}",
                rule_id="S3-ENC-MISSING",
                finding_type=FindingType.MISSING_EVIDENCE,
                severity=Severity.HIGH,
                title="Server-Side Encryption Configuration Omitted",
                description="The configuration does not specify a server_side_encryption block.",
                evidence={
                    "field_path": "configurations.server_side_encryption",
                    "observed": "null or missing",
                },
                why_it_matters=(
                    "Without explicit encryption settings, evidence of data-at-rest protection cannot be verified."
                ),
                remediation=(
                    "Define configurations.server_side_encryption with default SSE-KMS or AES256 encryption rules."
                ),
                confidence=Confidence.CERTAIN,
            )
        )
        return findings

    sse = configurations["server_side_encryption"]
    if not isinstance(sse, dict):
        return findings

    rules = sse.get("rules", [])
    if not rules or not isinstance(rules, list) or len(rules) == 0:
        findings.append(
            Finding(
                finding_id=f"S3-ENC-001:{resource_id}",
                rule_id="S3-ENC-001",
                finding_type=FindingType.CONFIRMED_RISK,
                severity=Severity.HIGH,
                title="S3 Server-Side Encryption Disabled",
                description="The server_side_encryption block contains an empty list of encryption rules.",
                evidence={
                    "field_path": "configurations.server_side_encryption.rules",
                    "observed_value": rules,
                },
                why_it_matters=(
                    "Unencrypted S3 buckets store objects in plaintext at rest, violating compliance standards "
                    "(e.g., SOC2, PCI-DSS) and increasing data leakage risk."
                ),
                remediation="Configure at least one rule with apply_server_side_encryption_by_default using aws:kms or AES256.",
                confidence=Confidence.CERTAIN,
            )
        )
    else:
        # Informational finding detailing active encryption
        first_rule = rules[0] if isinstance(rules[0], dict) else {}
        default_sse = first_rule.get("apply_server_side_encryption_by_default", {})
        algo = default_sse.get("sse_algorithm", "Unknown")
        findings.append(
            Finding(
                finding_id=f"S3-ENC-INFO:{resource_id}",
                rule_id="S3-ENC-INFO",
                finding_type=FindingType.INFORMATIONAL,
                severity=Severity.INFORMATIONAL,
                title=f"Server-Side Encryption Configured ({algo})",
                description=f"Bucket enforces server-side encryption at rest using {algo}.",
                evidence={
                    "field_path": "configurations.server_side_encryption.rules[0]",
                    "sse_algorithm": algo,
                    "bucket_key_enabled": first_rule.get("bucket_key_enabled", False),
                },
                why_it_matters="Data stored in the bucket is encrypted at rest.",
                remediation="No remediation required. Encryption is configured.",
                confidence=Confidence.CERTAIN,
            )
        )

    return findings


def check_server_access_logging(configurations: Dict[str, Any], resource_id: str) -> List[Finding]:
    """Check Server Access Logging configuration."""
    findings: List[Finding] = []

    if "server_access_logging" not in configurations or configurations["server_access_logging"] is None:
        findings.append(
            Finding(
                finding_id=f"S3-LOG-MISSING:{resource_id}",
                rule_id="S3-LOG-MISSING",
                finding_type=FindingType.MISSING_EVIDENCE,
                severity=Severity.LOW,
                title="Server Access Logging Configuration Omitted",
                description="The configuration does not specify a server_access_logging block.",
                evidence={
                    "field_path": "configurations.server_access_logging",
                    "observed": "null or missing",
                },
                why_it_matters="Audit logs cannot be verified if the logging configuration is omitted.",
                remediation="Define configurations.server_access_logging with enabled: true and a target_bucket.",
                confidence=Confidence.CERTAIN,
            )
        )
        return findings

    logging = configurations["server_access_logging"]
    if not isinstance(logging, dict):
        return findings

    is_enabled = logging.get("enabled", False)
    target_bucket = logging.get("target_bucket")

    if not is_enabled or not target_bucket:
        findings.append(
            Finding(
                finding_id=f"S3-LOG-001:{resource_id}",
                rule_id="S3-LOG-001",
                finding_type=FindingType.CONFIRMED_RISK,
                severity=Severity.MEDIUM,
                title="S3 Server Access Logging Disabled",
                description="Server access logging is either disabled (enabled: false) or missing a target_bucket.",
                evidence={
                    "field_path": "configurations.server_access_logging",
                    "enabled": is_enabled,
                    "target_bucket": target_bucket,
                },
                why_it_matters=(
                    "Without access logging, security incident response teams cannot audit access attempts, "
                    "detect anomalous downloads, or perform forensic investigations."
                ),
                remediation="Enable access logging and specify a dedicated central audit bucket for target_bucket.",
                confidence=Confidence.CERTAIN,
            )
        )
    else:
        findings.append(
            Finding(
                finding_id=f"S3-LOG-INFO:{resource_id}",
                rule_id="S3-LOG-INFO",
                finding_type=FindingType.INFORMATIONAL,
                severity=Severity.INFORMATIONAL,
                title="Server Access Logging Active",
                description=f"Access logs are delivered to target bucket: {target_bucket}.",
                evidence={
                    "field_path": "configurations.server_access_logging",
                    "target_bucket": target_bucket,
                    "target_prefix": logging.get("target_prefix", ""),
                },
                why_it_matters="Bucket access operations are recorded for auditing and forensic readiness.",
                remediation="No remediation required. Logging is active.",
                confidence=Confidence.CERTAIN,
            )
        )

    return findings


def check_versioning(configurations: Dict[str, Any], resource_id: str) -> List[Finding]:
    """Check S3 object versioning configuration."""
    findings: List[Finding] = []

    if "versioning" not in configurations or configurations["versioning"] is None:
        findings.append(
            Finding(
                finding_id=f"S3-VER-MISSING:{resource_id}",
                rule_id="S3-VER-MISSING",
                finding_type=FindingType.MISSING_EVIDENCE,
                severity=Severity.LOW,
                title="Versioning Configuration Omitted",
                description="The configuration does not specify a versioning configuration block.",
                evidence={
                    "field_path": "configurations.versioning",
                    "observed": "null or missing",
                },
                why_it_matters="Versioning status cannot be confirmed without explicit configuration.",
                remediation="Define configurations.versioning with status: 'Enabled'.",
                confidence=Confidence.CERTAIN,
            )
        )
        return findings

    versioning = configurations["versioning"]
    if not isinstance(versioning, dict):
        return findings

    status = versioning.get("status", "")
    if str(status).lower() not in ("enabled", "true"):
        findings.append(
            Finding(
                finding_id=f"S3-VER-001:{resource_id}",
                rule_id="S3-VER-001",
                finding_type=FindingType.CONFIRMED_RISK,
                severity=Severity.LOW,
                title="S3 Object Versioning Suspended or Disabled",
                description=f"Object versioning status is '{status}' rather than 'Enabled'.",
                evidence={
                    "field_path": "configurations.versioning.status",
                    "observed_value": status,
                },
                why_it_matters=(
                    "Disabling versioning leaves data vulnerable to accidental deletion, malicious overwrites, "
                    "or ransomware without recovery history."
                ),
                remediation="Set configurations.versioning.status to 'Enabled'.",
                confidence=Confidence.CERTAIN,
            )
        )

    return findings


def check_unsupported_fields(configurations: Dict[str, Any], resource_id: str) -> List[Finding]:
    """Detect unrecognized or unsupported configuration fields."""
    findings: List[Finding] = []

    unsupported = sorted(list(set(configurations.keys()) - KNOWN_S3_CONFIG_FIELDS))
    if unsupported:
        findings.append(
            Finding(
                finding_id=f"S3-CFG-UNSUPPORTED:{resource_id}",
                rule_id="S3-CFG-UNSUPPORTED",
                finding_type=FindingType.INFORMATIONAL,
                severity=Severity.INFORMATIONAL,
                title="Unrecognized Configuration Fields Detected",
                description=(
                    f"Configuration contains {len(unsupported)} field(s) outside known S3 specification: "
                    f"{', '.join(unsupported)}."
                ),
                evidence={
                    "field_path": "configurations",
                    "unrecognized_fields": unsupported,
                    "supported_fields": sorted(list(KNOWN_S3_CONFIG_FIELDS)),
                },
                why_it_matters=(
                    "Unrecognized fields are ignored during security evaluation and may represent typos or "
                    "unsupported provider properties."
                ),
                remediation="Verify field spelling against the ShipSafe AI S3 configuration schema specification.",
                confidence=Confidence.HIGH,
            )
        )

    return findings
