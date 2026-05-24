FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps for paramiko's cryptography wheels (mostly already in slim image,
# but build deps cover edge cases on arm64 etc.).
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY honeypot ./honeypot
COPY config.yaml.example ./config.yaml.example

# Persistent state (host key + logs) lives on a volume.
RUN mkdir -p /data/logs
VOLUME ["/data"]

# 22   = SSH honeypot (the real foothold)
# 80   = decoy "vulnerable" website (bait that funnels to SSH)
# 8080 = operator dashboard
EXPOSE 22 80 8080

CMD ["python", "-m", "honeypot.main"]
