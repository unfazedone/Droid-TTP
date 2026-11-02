# ==============================================================================
# DroidTTP Production Dockerfile
# Multi-stage, unprivileged, hardened container image
# ==============================================================================

# Stage 1: Build virtual environment and wheels
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install --no-install-recommends -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# Stage 2: Final minimal production image
FROM python:3.11-slim-bookworm AS runtime

LABEL maintainer="DroidTTP Security Team" \
      description="DroidTTP - Android Application to TTP Mapping for Cyber Threat Intelligence" \
      version="1.0.0"

# Install runtime dependencies only
RUN apt-get update && apt-get install --no-install-recommends -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root service user and group
RUN groupadd --gid 10001 droidttp \
    && useradd --uid 10001 --gid droidttp --shell /usr/sbin/nologin --home-dir /app droidttp

WORKDIR /app

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DROIDTTP_DATA_DIR=/app/data

# Copy application source code
COPY --chown=droidttp:droidttp app /app/app

# Create data directory structure with restricted permissions
RUN mkdir -p /app/data/samples \
    && chown -R droidttp:droidttp /app/data \
    && chmod 700 /app/data /app/data/samples

# Switch to non-root user
USER droidttp

# Expose internal application port
EXPOSE 8000

# Health check probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/healthz || exit 1

# Production entrypoint with Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips", "*"]
