FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install grype and osv-scanner
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY . /build
RUN pip install --no-cache-dir /build[all] && rm -rf /build

WORKDIR /project

ENTRYPOINT ["sbom"]
