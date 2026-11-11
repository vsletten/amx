FROM python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libmilter-dev openssl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv==0.5.24
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY LICENSE NOTICE LICENSE.gateway ./
# pymilter, patched for libmilter's worker pool (third_party/pymilter/AMX.md); uv builds it here.
COPY third_party ./third_party
COPY src ./src
COPY spec ./spec
RUN uv sync --frozen --no-dev --group gateway \
    && rm -rf /root/.cache

EXPOSE 2424 2587 8890
ENTRYPOINT ["/app/.venv/bin/amx-gateway"]
