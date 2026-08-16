# ================================
# Vorsyghta API - Production Dockerfile
# ================================
# Multi-stage build for optimized container size

# Stage 1: Builder
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt requirements-dev.txt ./

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python packages (including dev dependencies for demo/test runs)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements-dev.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Set labels
LABEL maintainer="Vorsyghta Team"
LABEL description="Vorsyghta - AI-Powered Threat Simulation Platform"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app:$PYTHONPATH" \
    HOME="/app"

# Create app user
RUN groupadd -r vorsyghta && useradd -r -g vorsyghta vorsyghta

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY --chown=vorsyghta:vorsyghta vorsyghta/ /app/vorsyghta/
COPY --chown=vorsyghta:vorsyghta templates/ /app/templates/
COPY --chown=vorsyghta:vorsyghta config.yaml /app/
COPY --chown=vorsyghta:vorsyghta pyproject.toml /app/
COPY --chown=vorsyghta:vorsyghta migrations/ /app/migrations/
COPY --chown=vorsyghta:vorsyghta demos/ /app/demos/
COPY --chown=vorsyghta:vorsyghta tests/ /app/tests/
COPY --chown=vorsyghta:vorsyghta alembic.ini /app/

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/generated_content /app/reports /app/output && \
    chown -R vorsyghta:vorsyghta /app

# Switch to app user
USER vorsyghta

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command - run API server
CMD ["python", "-m", "uvicorn", "vorsyghta.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
