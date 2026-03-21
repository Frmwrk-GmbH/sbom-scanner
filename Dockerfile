# ── Stage 1: Build ──
FROM python:3.13-alpine AS builder

RUN apk add --no-cache git
COPY . /build
RUN pip install --no-cache-dir --prefix=/install /build[yaml,python]

# ── Stage 2: Tools ──
FROM alpine:3.21 AS tools

RUN apk add --no-cache curl \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /tools \
    && curl -sSfL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /tools/osv-scanner \
    && chmod +x /tools/osv-scanner

# ── Stage 3: Final ──
FROM python:3.13-alpine

# Runtime deps only
RUN apk add --no-cache git libstdc++

# Python packages from builder
COPY --from=builder /install /usr/local

# CVE scanning tools
COPY --from=tools /tools/grype /usr/local/bin/
COPY --from=tools /tools/osv-scanner /usr/local/bin/

WORKDIR /project

ENTRYPOINT ["sbom"]
