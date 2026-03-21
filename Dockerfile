# ── Stage 1: Build ──
FROM python:3.13-alpine AS builder

ARG VERSION=0.0.0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${VERSION}

RUN apk add --no-cache gcc musl-dev
COPY . /build
WORKDIR /build
RUN pip install --no-cache-dir build hatch-vcs \
    && pip install --no-cache-dir --prefix=/install ".[yaml,python]"

# ── Stage 2: Tools ──
FROM alpine:3.21 AS tools

RUN apk add --no-cache curl bash \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | bash -s -- -b /tools \
    && curl -sSfL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /tools/osv-scanner \
    && chmod +x /tools/osv-scanner

# ── Stage 3: Final ──
FROM python:3.13-alpine

RUN apk add --no-cache git libstdc++

COPY --from=builder /install /usr/local
COPY --from=tools /tools/grype /usr/local/bin/
COPY --from=tools /tools/osv-scanner /usr/local/bin/

WORKDIR /project

ENTRYPOINT ["sbom"]
