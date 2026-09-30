# Reproducible Security Gate runner.
# Every scanner is pinned to an exact version and verified against the
# vendor's published SHA-256 checksum, so two builds scan with identical tools.
FROM python:3.12-slim-bookworm

ARG SEMGREP_VERSION=1.178.0
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG TRIVY_VERSION=0.74.0
ARG TRIVY_SHA256=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
ARG SYFT_VERSION=1.52.0
ARG SYFT_SHA256=caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    TRIVY_CACHE_DIR=/opt/trivy-cache \
    TRIVY_NO_PROGRESS=true

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates jq time \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; cd /tmp; \
    curl -fsSLo gl.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    echo "${GITLEAKS_SHA256}  gl.tgz" | sha256sum -c -; \
    tar -xzf gl.tgz -C /usr/local/bin gitleaks; \
    curl -fsSLo tv.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    echo "${TRIVY_SHA256}  tv.tgz" | sha256sum -c -; \
    tar -xzf tv.tgz -C /usr/local/bin trivy; \
    curl -fsSLo sy.tgz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz"; \
    echo "${SYFT_SHA256}  sy.tgz" | sha256sum -c -; \
    tar -xzf sy.tgz -C /usr/local/bin syft; \
    rm -f /tmp/*.tgz

COPY requirements.txt /opt/gate/requirements.txt
RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" -r /opt/gate/requirements.txt

# Snapshot the Semgrep Registry rulesets and the Trivy vulnerability DB at build
# time. Scans then run offline against a frozen rule/CVE snapshot, which keeps
# repeated runs comparable (the registry and the CVE feed change daily).
COPY scripts/snapshot_rules.sh /opt/gate/scripts/snapshot_rules.sh
RUN bash /opt/gate/scripts/snapshot_rules.sh /opt/gate/rules/registry \
 && trivy image --download-db-only --no-progress \
 && trivy --version > /opt/gate/TOOL_VERSIONS.txt \
 && echo "semgrep $(semgrep --version)" >> /opt/gate/TOOL_VERSIONS.txt \
 && echo "gitleaks $(gitleaks version)" >> /opt/gate/TOOL_VERSIONS.txt \
 && echo "syft $(syft version | awk '/^Version/{print $2}')" >> /opt/gate/TOOL_VERSIONS.txt

COPY . /opt/gate
RUN git config --system --add safe.directory '*' \
 && git config --system user.email "gate@localhost" \
 && git config --system user.name "security-gate"

ENV PATH="/opt/gate/scripts:${PATH}"
WORKDIR /work
ENTRYPOINT ["python", "/opt/gate/gate/cli.py"]
