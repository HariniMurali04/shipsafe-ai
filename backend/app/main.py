"""ShipSafe AI - Main FastAPI Application Entrypoint.

Tagline: Secure Every Change Before It Ships.
"""

import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router as api_router
from app.assistant import assistant_router
from app.schemas import RootInfoResponse

app = FastAPI(
    title="ShipSafe AI",
    description=(
        "ShipSafe AI is an intelligent AWS configuration security and "
        "deployment-readiness advisor. Secure Every Change Before It Ships."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS for local development and frontend integration
cors_origins_env = os.getenv("CORS_ORIGINS", "*")
allowed_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers under the /api prefix
app.include_router(api_router, prefix="/api", tags=["Core API"])
app.include_router(assistant_router, prefix="/api", tags=["ShipSafe Assistant"])


@app.get(
    "/",
    response_model=RootInfoResponse,
    summary="ShipSafe AI Service Info",
    tags=["Root"],
)
async def root() -> RootInfoResponse:
    """Return welcome metadata and links to documentation and core API endpoints."""
    return RootInfoResponse(
        app_name="ShipSafe AI",
        tagline="Secure Every Change Before It Ships.",
        version="0.1.0",
        documentation_url="/docs",
        health_endpoint="/api/health",
        features_endpoint="/api/features",
    )


if __name__ == "__main__":
    host = os.getenv("APP_HOST", "127.0.0.1")
    port = int(os.getenv("APP_PORT", "8000"))
    uvicorn.run("app.main:app", host=host, port=port, reload=True)
