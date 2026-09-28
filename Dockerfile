# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Install system build dependencies and runtime C libraries needed for pqcrypto, PyMuPDF, and OpenCV
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first to leverage Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source tree
COPY . .

# Ensure storage directories exist at runtime
RUN python -c "import store; store.ensure_dirs()" || true

# Default port configuration for Render / Cloud
ENV PORT=10000
ENV PYTHONUNBUFFERED=1

EXPOSE 10000

# Production WSGI server binding to 0.0.0.0 on dynamic $PORT
CMD exec gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 2 --threads 4 --timeout 120 app:app
