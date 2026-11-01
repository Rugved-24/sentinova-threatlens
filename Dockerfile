FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    THREATLENS_ENV_FILE=/app/.env

RUN groupadd --gid 10001 threatlens \
    && useradd --uid 10001 --gid threatlens --create-home --shell /usr/sbin/nologin threatlens

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY data/attack_techniques.json ./data/attack_techniques.json
COPY --from=web /web/dist ./frontend/dist

RUN mkdir -p /app/data/reports /app/data/exports \
    && chown -R threatlens:threatlens /app/data /app/frontend

USER threatlens
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/ready', timeout=3)"

CMD ["uvicorn", "app.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
