# syntax=docker/dockerfile:1
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY . .
RUN groupadd -g 10001 app && useradd -r -u 10001 -g app app && mkdir -p /data && chown -R app:app /app /data
ENV DATABASE_URL=sqlite:////data/syslog.db
EXPOSE 8000/tcp 5514/udp 5515/tcp
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -fsS http://localhost:8000/ >/dev/null || exit 1
USER app
CMD ["python","app.py"]
