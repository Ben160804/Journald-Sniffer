FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libsystemd0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# /ingest requires a real Linux host with systemd journal.
# In Docker it will return 501 unless the container is privileged
# and shares /run/systemd/journal with the host.

ENV DB_HOST=${DB_HOST:-db}
ENV DB_NAME=${DB_NAME:-watchdog}
ENV DB_USER=${DB_USER:-watchdog}
ENV DB_PASS=${DB_PASS:-watchdog}
ENV GROQ_API_KEY=${GROQ_API_KEY:-}

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
