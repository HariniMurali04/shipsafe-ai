"""Pydantic data schemas for ShipSafe AI API requests and responses."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

# Re-export engine models for unified schema imports
from app.engine.models import (
    AnalysisResponse,
    Confidence,
    Finding,
    FindingType,
    Severity,
    VerificationItem,
    VerificationResponse,
    VerificationStatus,
)


class HealthResponse(BaseModel):
    """Schema for system health check status."""

    status: str = Field(
        default="healthy",
        description="Current health status of the application service",
        examples=["healthy"],
    )
    app_name: str = Field(
        default="ShipSafe AI",
        description="Name of the application",
        examples=["ShipSafe AI"],
    )
    tagline: str = Field(
        default="Secure Every Change Before It Ships.",
        description="Application tagline",
        examples=["Secure Every Change Before It Ships."],
    )
    version: str = Field(
        default="0.1.0",
        description="API semantic version",
        examples=["0.1.0"],
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the health check query",
    )


class FeatureItem(BaseModel):
    """Schema describing an individual feature capability."""

    id: str = Field(..., description="Unique identifier for the feature")
    name: str = Field(..., description="Human-readable feature name")
    description: str = Field(..., description="Detailed description of what the feature does")
    status: Literal["implemented", "in_progress", "planned"] = Field(
        ...,
        description="Current development lifecycle status of this capability",
    )
    endpoint: str | None = Field(
        default=None,
        description="Associated API endpoint if currently available",
    )


class FeaturesResponse(BaseModel):
    """Schema for listing currently implemented and planned platform capabilities."""

    total_features: int = Field(..., description="Total number of cataloged features")
    implemented_count: int = Field(..., description="Count of currently implemented features")
    features: List[FeatureItem] = Field(..., description="List of platform features")


class RootInfoResponse(BaseModel):
    """Schema for the API root information endpoint."""

    app_name: str
    tagline: str
    version: str
    documentation_url: str
    health_endpoint: str
    features_endpoint: str


class AnalyzeRequest(BaseModel):
    """Request payload for POST /api/analyze."""

    configuration: Optional[Dict[str, Any]] = Field(
        default=None,
        description="S3 configuration dictionary. Can also be provided directly as root object.",
    )

    model_config = {"extra": "allow"}


class VerifyRequest(BaseModel):
    """Request payload for POST /api/verify."""

    configuration: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Updated S3 configuration dictionary. Can also be provided directly in root.",
    )
    finding_ids: Optional[List[str]] = Field(
        default=None,
        description="Optional list of finding IDs to verify resolution for",
    )
    rule_ids: Optional[List[str]] = Field(
        default=None,
        description="Optional list of rule IDs to verify resolution for",
    )

    model_config = {"extra": "allow"}
