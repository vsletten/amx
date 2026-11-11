# syntax=docker/dockerfile:1
# LOCAL BUILD ONLY: init, sync and probe copy SEL-only upstream code. Never publish this image.
# M6: one-shot provisioning for contoso's Stalwart mailhost (deploy/compose.stalwart.yaml).
# The mailhost itself runs the pinned Stalwart Community image unmodified. This image copies that
# image's binary, adds the official stalwart-cli (checksum-verified), and runs
# amx.adapters.stalwart to write the settings and accounts into the mailhost's data volume.
FROM stalwartlabs/stalwart:v0.16.25@sha256:74e5a7d55303ba525d939c6bf97ed4e010df7521f52d80afc22a815b66bd53f3 AS stalwart

FROM python:3.13-slim AS provisioner
ARG TARGETARCH
ARG STALWART_CLI_VERSION=v1.0.12
ARG STALWART_CLI_SHA256_AMD64=76fcd7250a10c7bee704dc4a08000b3faca6b5a22895d41831c0c37efd95acce
ARG STALWART_CLI_SHA256_ARM64=59dff5d52180df669eec705eb3fe2b80cee9267291e88123bd72af855d4c5bc3

COPY --from=stalwart /usr/local/bin/stalwart /usr/local/bin/stalwart
RUN python - <<'EOF'
import hashlib, io, os, tarfile, urllib.request

arch = os.environ["TARGETARCH"]
target = {"amd64": "x86_64", "arm64": "aarch64"}[arch] + "-unknown-linux-musl"
expected = os.environ[f"STALWART_CLI_SHA256_{arch.upper()}"]
version = os.environ["STALWART_CLI_VERSION"]
url = (
    f"https://github.com/stalwartlabs/cli/releases/download/{version}/"
    f"stalwart-cli-{target}.tar.xz"
)
data = urllib.request.urlopen(url, timeout=60).read()
digest = hashlib.sha256(data).hexdigest()
if digest != expected:
    raise SystemExit(f"stalwart-cli checksum mismatch: {digest} != {expected}")
with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
    member = archive.getmember(f"stalwart-cli-{target}/stalwart-cli")
    with open("/usr/local/bin/stalwart-cli", "wb") as out:
        out.write(archive.extractfile(member).read())
os.chmod("/usr/local/bin/stalwart-cli", 0o755)
EOF

COPY src/amx/adapters/stalwart.py /opt/amx/stalwart.py
COPY tools/stalwart_probe.py /opt/amx/stalwart_probe.py
# The same uid the Stalwart image runs as, so the provisioned volume is the mailhost's.
RUN groupadd --gid 2000 stalwart \
    && useradd --uid 2000 --gid 2000 --no-create-home stalwart \
    && install -d -o 2000 -g 2000 /etc/stalwart /var/lib/stalwart
USER 2000:2000
# stalwart-cli keeps state under $HOME; uid 2000 has no home directory.
ENV HOME=/tmp
ENTRYPOINT ["python", "/opt/amx/stalwart.py", "provision"]

# SH-00 signature verification dependencies match uv.lock. The ordinary init
# and sync services target provisioner and remain standard-library-only.
FROM provisioner AS probe
USER root
RUN pip install --no-cache-dir dkimpy==1.1.8 dnspython==2.8.0
USER 2000:2000
