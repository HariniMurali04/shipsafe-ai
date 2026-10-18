# ==============================================================================
# ShipSafe AI - Backend Dockerfile
# Tagline: Secure Every Change Before It Ships.
# Zero AWS Credentials Required to build or run.
# ==============================================================================

FROM python:3.11-slim AS runtime

# Set runtime environment flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend \
    APP_ENV=production \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000 \
    BEDROCK_ENABLED=false

# Create non-root application user for container security
RUN groupadd --gid 1000 shipsafe && \
    useradd --uid 1000 --gid 1000 --create-home shipsafe

WORKDIR /app

# Install dependencies as cached layer
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend application source and synthetic sample files
COPY backend /app/backend
COPY samples /app/samples

# Grant non-root ownership
RUN chown -R shipsafe:shipsafe /app

USER shipsafe

EXPOSE 8000

# Container healthcheck using built-in Python standard library
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

# Launch FastAPI backend with Uvicorn
WORKDIR /app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
