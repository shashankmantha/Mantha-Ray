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
    && freshclam \
    && /opt/capa-venv/bin/capa --version \
    && /opt/floss-venv/bin/floss --version \
    && rm -f \
        /tmp/capa-rules.zip \
        /tmp/capa-source.zip \
    && rm -rf \
        /tmp/capa-source \
        /root/.cache \
    && apk del .analysis-build-deps

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