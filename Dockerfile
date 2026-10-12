# CoreSight Vault - production image
FROM python:3.12-slim

# DejaVu fonts: full Unicode in playbook PDFs. tzdata: lets TZ=... in .env set local time for scheduled jobs
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////data/coresight.db \
    UPLOAD_DIR=/data/uploads \
    BACKUP_DIR=/data/backups

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN useradd --create-home --uid 1000 vault && mkdir -p /data && chown -R vault:vault /data /app
USER vault

VOLUME ["/data"]
EXPOSE 5001
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5001/login', timeout=4)" || exit 1
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5001", "--access-logfile", "-", "app:app"]
