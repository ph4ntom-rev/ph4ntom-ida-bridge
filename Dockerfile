FROM python:3.11-slim

WORKDIR /app

ENV IDA_BRIDGE_ALLOW_DOCKER_HOST=1

COPY . /app

RUN pip install --no-cache-dir ".[mcp]"

ENTRYPOINT ["python", "mcp_server.py"]
