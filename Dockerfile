# E2E-V pilot image. Single worker on purpose: SQLite and the in-memory rate
# limiter are not safe to share across processes.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    EVOTING_DB=/app/data/evoting.db

WORKDIR /app

# opencv-python-headless still needs libglib; no GUI/X libraries are installed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system evoting \
    && useradd --system --gid evoting --home-dir /app evoting

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=evoting:evoting . .

# The database, the authority signing key and backups live on the mounted volume.
RUN mkdir -p /app/data && chown evoting:evoting /app/data

USER evoting

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status == 200 else 1)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
