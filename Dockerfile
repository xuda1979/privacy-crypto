# syntax=docker/dockerfile:1.6
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# Default to API + P2P together (two processes). In compose we run them separately.
ENV HOST=0.0.0.0 PORT=8000 \
    P2P_HOST=0.0.0.0 P2P_PORT=9000

EXPOSE 8000 9000

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["/bin/sh","-c","set -e; \
  if [ -n \"${UVLOOP:-}\" ]; then echo '[docker] uvloop enabled'; fi; \
  ./scripts/run_node.sh & \
  ./scripts/run_p2p.sh & \
  wait -n; exit $?"]
