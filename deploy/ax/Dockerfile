# Both stages use Debian bookworm. cgo links sqlite against the runner's actual libc.
FROM golang:1.24.5-bookworm AS ax-build
RUN apt-get update && apt-get install -y --no-install-recommends git gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/ax/AX_COMMIT /AX_COMMIT
RUN git init /ax-src && cd /ax-src \
    && git remote add origin https://github.com/summationai/agent-exchange \
    && git fetch --depth=1 origin "$(cat /AX_COMMIT)" && git checkout --detach FETCH_HEAD
WORKDIR /ax-src
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -o /ax ./cmd/ax

FROM python:3.13-slim-bookworm
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir uv==0.5.24
COPY --from=ax-build /ax /usr/local/bin/ax
# Verify the actual dynamic dependencies in the runtime stage, not a base-image assumption.
RUN ldd /usr/local/bin/ax && /usr/local/bin/ax version
ARG AMX_UID=1000
ARG AMX_GID=1000
RUN mkdir /state && chown ${AMX_UID}:${AMX_GID} /state && chmod 0700 /state
# Compose may run an arbitrary numeric UID without a writable HOME. All image
# entrypoints (runner, MCP and scenario overrides) share custody on this volume.
ENV XDG_STATE_HOME=/state
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY LICENSE NOTICE ./
COPY third_party ./third_party
COPY src ./src
COPY spec ./spec
RUN uv sync --frozen --no-dev && rm -rf /root/.cache
ENTRYPOINT ["/app/.venv/bin/amx-runner"]
