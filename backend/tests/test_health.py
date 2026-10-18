"""Unit and integration tests for ShipSafe AI health and features API endpoints."""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure backend root is on sys.path for direct pytest invocation
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.main import app

client = TestClient(app)


def test_health_endpoint_success() -> None:
    """Test that GET /api/health returns HTTP 200 with valid JSON status."""
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "ShipSafe AI"
    assert data["tagline"] == "Secure Every Change Before It Ships."
    assert data["version"] == "0.1.0"
    assert "timestamp" in data


def test_features_endpoint_success() -> None:
    """Test that GET /api/features returns implemented and planned capabilities."""
    response = client.get("/api/features")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert "features" in data
    assert "total_features" in data
    assert "implemented_count" in data
    assert data["total_features"] > 0
    assert data["implemented_count"] >= 2

    # Verify each feature conforms to required structure
    features = data["features"]
    feature_ids = [f["id"] for f in features]
    assert "api-health-check" in feature_ids
    assert "feature-discovery" in feature_ids

    for feat in features:
        assert "id" in feat
        assert "name" in feat
        assert "description" in feat
        assert feat["status"] in ("implemented", "in_progress", "planned")


def test_root_endpoint_metadata() -> None:
    """Test that GET / returns API metadata and valid endpoint routes."""
    response = client.get("/")

    assert response.status_code == 200
    data = response.json()
    assert data["app_name"] == "ShipSafe AI"
    assert data["documentation_url"] == "/docs"
    assert data["health_endpoint"] == "/api/health"
    assert data["features_endpoint"] == "/api/features"
