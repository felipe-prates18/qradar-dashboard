FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        build-essential \
        bash \
        libffi-dev \
        libssl-dev \
        sqlite3 \
        openssh-server \
        vim && \
    rm -rf /var/lib/apt/lists/*

# Habilita diretório do SSH
RUN mkdir -p /var/run/sshd

# Symlink python
RUN ln -s /usr/bin/python3 /usr/bin/python || true

# Configura senha root e habilita login root + autenticação por senha
RUN echo "root:mp1066*2G*" | chpasswd && \
    sed -i 's/#\?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config

WORKDIR /opt/qradar-dashboard

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

EXPOSE 22
EXPOSE 9030

CMD ["/bin/bash", "-c", "/usr/sbin/sshd && exec uvicorn app.main:app --host 0.0.0.0 --port 9030 --no-server-header --log-config /opt/qradar-dashboard/logging.ini"]
