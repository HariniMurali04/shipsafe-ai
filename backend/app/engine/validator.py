"""Input validation module for synthetic AWS S3 configuration payloads."""

from typing import Any, Dict, Tuple


class ConfigurationValidationError(Exception):
    """Raised when an input configuration is malformed or invalid."""

    def __init__(self, message: str, details: Dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


SUPPORTED_CONFIG_TYPES = {"AWS::S3::Bucket", "aws:s3:bucket", "S3::Bucket"}


def validate_s3_configuration_payload(data: Any) -> Tuple[Dict[str, Any], str]:
    """Validate structure of synthetic S3 configuration.

    Returns:
        Tuple of (normalized_configuration_dict, resource_id)

    Raises:
        ConfigurationValidationError: If JSON structure or configuration_type is invalid.
    """
    if not isinstance(data, dict):
        raise ConfigurationValidationError(
            "Input payload must be a JSON object (dictionary).",
            {"received_type": type(data).__name__},
        )

    # Check configuration_type
    config_type = data.get("configuration_type")
    if not config_type:
        raise ConfigurationValidationError(
            "Missing required top-level property 'configuration_type'.",
            {
                "expected": "AWS::S3::Bucket",
                "received": None,
                "hint": "Ensure 'configuration_type': 'AWS::S3::Bucket' is defined in the JSON root.",
            },
        )

    if str(config_type).strip() not in SUPPORTED_CONFIG_TYPES:
        raise ConfigurationValidationError(
            f"Unsupported configuration_type '{config_type}'.",
            {
                "supported_types": sorted(list(SUPPORTED_CONFIG_TYPES)),
                "received": config_type,
                "hint": "ShipSafe AI currently evaluates synthetic 'AWS::S3::Bucket' configurations.",
            },
        )

    # Extract configurations block
    configurations = data.get("configurations")
    if configurations is None:
        raise ConfigurationValidationError(
            "Missing required top-level property 'configurations'.",
            {
                "hint": "The configuration must include a 'configurations' dictionary containing bucket settings.",
            },
        )

    if not isinstance(configurations, dict):
        raise ConfigurationValidationError(
            "Property 'configurations' must be a JSON object (dictionary).",
            {"received_type": type(configurations).__name__},
        )

    # Extract resource identifier for deterministic correlation
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    resource_id = (
        metadata.get("resource_id")
        or metadata.get("bucket_name")
        or data.get("resource_id")
        or "synthetic-s3-bucket"
    )

    return data, str(resource_id)
