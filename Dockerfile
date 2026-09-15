FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NOVA_HOST=0.0.0.0 \
    NOVA_CDP_HOST=127.0.0.1 \
    NOVA_CDP_PORT=9222 \
    CHROMIUM_BIN=/usr/bin/chromium

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium ca-certificates fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY serveur_render.py ./serveur.py

EXPOSE 10000
CMD ["python", "serveur.py"]
