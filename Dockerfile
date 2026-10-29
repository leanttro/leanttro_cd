FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/data/etica.db \
    PORT=5000

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates ./templates

# Pasta persistente (monte um volume aqui no Dokploy)
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 5000

# 1 worker + threads: seguro para SQLite e mantém a sessão consistente
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT} --workers 1 --threads 4 --timeout 60"]
