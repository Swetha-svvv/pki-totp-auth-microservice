# ---------- Stage 1: Builder ----------
FROM python:3.11-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

# Install build tools and python deps globally
COPY requirements.txt /app/requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc \
    && pip install --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && apt-get purge -y --auto-remove build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy application source
COPY . /app

# ---------- Stage 2: Runtime ----------
FROM python:3.11-slim AS runtime
ENV TZ=UTC
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

# Install cron and timezone data
RUN apt-get update && \
    apt-get install -y --no-install-recommends cron tzdata ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Configure timezone to UTC
RUN ln -sf /usr/share/zoneinfo/UTC /etc/localtime && echo "UTC" > /etc/timezone

# Copy python installation (site-packages, scripts) from builder
COPY --from=builder /usr/local /usr/local

# Copy application code (includes cron/, scripts/, keys, etc.)
COPY --from=builder /app /app

# Install cron job
RUN chmod 0644 /app/cron/2fa-cron || true && crontab /app/cron/2fa-cron || true

# Create persistent mount points
RUN mkdir -p /data /cron && chmod 0755 /data /cron
VOLUME ["/data", "/cron"]

# Make sure start.sh is executable
RUN chmod +x /app/start.sh || true

EXPOSE 8080

# Start cron and the app server
CMD ["sh", "-c", "cron || true; sleep 1; ./start.sh"]
