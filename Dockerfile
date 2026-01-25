FROM python:3.11-slim

WORKDIR /opt/qradar-dashboard

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       bash \
       libffi-dev \
       libssl-dev \
       sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# >>> CRIAR DIRETÓRIO DE LOG AQUI <<<
RUN mkdir -p /var/log/qradarapp

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY deploy.sh .
COPY logging.ini .
COPY users.db .
COPY alerts_state.json .
COPY keys ./keys

ENV PYTHONPATH=/opt/qradar-dashboard

CMD ["bash", "-c", "chmod +x ./deploy.sh && ./deploy.sh"]
