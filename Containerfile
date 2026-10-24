FROM clamav/clamav:1.5

USER root

ARG CAPA_VERSION=9.4.0
ARG FLOSS_VERSION=3.1.1

RUN apk add --no-cache \
        python3 \
        libgcc \
        libstdc++ \
    && apk add --no-cache \
        --virtual .analysis-build-deps \
        py3-pip \
        python3-dev \
        curl \
        unzip \
        build-base \
        cargo \
    && python3 -m venv /opt/capa-venv \
    && /opt/capa-venv/bin/pip install \
        --no-cache-dir \
        --upgrade pip \
    && /opt/capa-venv/bin/pip install \
        --no-cache-dir \
        "flare-capa==${CAPA_VERSION}" \
    && python3 -m venv /opt/floss-venv \
    && /opt/floss-venv/bin/pip install \
        --no-cache-dir \
        --upgrade pip \
    && /opt/floss-venv/bin/pip install \
        --no-cache-dir \
        "flare-floss==${FLOSS_VERSION}" \
    && curl \
        --fail \
        --silent \
        --show-error \
        --location \
        "https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_VERSION}.zip" \
        --output /tmp/capa-rules.zip \
    && unzip \
        -q \
        /tmp/capa-rules.zip \
        -d /opt \
    && mv \
        "/opt/capa-rules-${CAPA_VERSION}" \
        /opt/capa-rules \
    && curl \
        --fail \
        --silent \
        --show-error \
        --location \
        "https://github.com/mandiant/capa/archive/refs/tags/v${CAPA_VERSION}.zip" \
        --output /tmp/capa-source.zip \
    && unzip \
        -q \
        /tmp/capa-source.zip \
        -d /tmp/capa-source \
    && mv \
        "/tmp/capa-source/capa-${CAPA_VERSION}/sigs" \
        /opt/capa-sigs \
    && find \
        /opt/capa-sigs \
        -type f \
        -name '*.sig' \
        -print \
        -quit \
        | grep -q . \
    && /opt/capa-venv/bin/capa --version \
    && /opt/floss-venv/bin/floss --version \
    && rm -f \
        /tmp/capa-rules.zip \
        /tmp/capa-source.zip \
    && rm -rf \
        /tmp/capa-source \
        /root/.cache \
    && apk del .analysis-build-deps


# YARA-X command-line scanner. The release binary is fully static, so it runs
# on this Alpine (musl) image; the archive is checked against a pinned hash.
# Hermit pins the same version for the rule bundles it builds.
ARG YARA_X_VERSION=1.22.0
ARG YARA_X_SHA256=7f470770b2c1a0d97f02298fc194978d999074d147d003d33dd62775761439db
RUN apk add --no-cache --virtual .yara-x-fetch curl \
    && curl \
        --fail \
        --silent \
        --show-error \
        --location \
        "https://github.com/VirusTotal/yara-x/releases/download/v${YARA_X_VERSION}/yara-x-v${YARA_X_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
        --output /tmp/yara-x.tar.gz \
    && echo "${YARA_X_SHA256}  /tmp/yara-x.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/yara-x.tar.gz -C /usr/local/bin yr \
    && chmod 0755 /usr/local/bin/yr \
    && rm -f /tmp/yara-x.tar.gz \
    && /usr/local/bin/yr --version \
    && apk del .yara-x-fetch


ARG CLAMAV_DB_REFRESH=unset
RUN printf 'Refreshing ClamAV signatures (%s)\n' "${CLAMAV_DB_REFRESH}" \
    && freshclam

WORKDIR /opt/static-triage

COPY src ./src
COPY pyproject.toml README.md ./

ENV PATH="/opt/floss-venv/bin:/opt/capa-venv/bin:/usr/local/bin:/usr/bin:/bin"
ENV CAPA_RULES_PATH=/opt/capa-rules
ENV CAPA_SIGNATURES_PATH=/opt/capa-sigs
ENV PYTHONPATH=/opt/static-triage/src
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "-m", "static_triage.cli"]

# The ClamAV base image checks a clamd service we never start, which made
# every scan container show as "unhealthy". Scans use clamscan instead.
HEALTHCHECK NONE