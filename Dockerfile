FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 nftables tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY gamebond ./gamebond
# Explicit runtime crypto version, compatible with pyproject.toml. The local
# GameBond package is installed from this build context; no remote app package.
RUN python -m pip install --no-cache-dir "cryptography==46.0.7" \
    && python -m pip install --no-cache-dir --no-deps .

COPY tools/container-entrypoint.sh /usr/local/bin/container-entrypoint
RUN chmod 0755 /usr/local/bin/container-entrypoint

EXPOSE 4433/udp
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/container-entrypoint"]
