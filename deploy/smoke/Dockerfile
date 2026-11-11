FROM docker:27-cli

# pytest from PyPI at the version uv.lock pins: Alpine 3.21's py3-pytest is 8.3.x, older than the
# 9.0.3 tmpdir fix.
RUN apk add --no-cache python3 py3-pip \
    && pip install --no-cache-dir --break-system-packages --root-user-action=ignore pytest==9.1.1

ENTRYPOINT []
