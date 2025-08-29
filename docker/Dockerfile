# SLSA Level 3 Security Tools Container for Jenkins
# This image provides all security tools needed for SLSA Level 3 compliance
FROM alpine:3.19

LABEL maintainer="DevSecOps Team <devsecops@kubectl.shop>"
LABEL description="Jenkins security agent with SLSA Level 3 tools"
LABEL version="1.0.0"

# Install base packages and dependencies
RUN apk add --no-cache \
    bash \
    curl \
    git \
    jq \
    yq \
    python3 \
    py3-pip \
    openjdk17-jre \
    docker-cli \
    kubectl \
    helm \
    ca-certificates \
    openssl \
    tar \
    gzip \
    findutils \
    coreutils

# Security tool versions
ENV TRIVY_VERSION=0.48.3
ENV COSIGN_VERSION=2.2.4
ENV SLSA_VERIFIER_VERSION=2.4.1
ENV SYFT_VERSION=0.98.0
ENV GRYPE_VERSION=0.74.1
ENV BUILDPACK_VERSION=0.32.0

# Install Trivy for vulnerability scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
    sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# Install Cosign for signing and attestation
RUN curl -sLO https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64 && \
    mv cosign-linux-amd64 /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# Install SLSA Verifier for provenance verification
RUN curl -sLO https://github.com/slsa-framework/slsa-verifier/releases/download/v${SLSA_VERIFIER_VERSION}/slsa-verifier-linux-amd64 && \
    mv slsa-verifier-linux-amd64 /usr/local/bin/slsa-verifier && \
    chmod +x /usr/local/bin/slsa-verifier

# Install Syft for SBOM generation
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
    sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Install Grype for vulnerability assessment
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
    sh -s -- -b /usr/local/bin v${GRYPE_VERSION}

# Install pack CLI for buildpack support (future extensibility)
RUN curl -sSL "https://github.com/buildpacks/pack/releases/download/v${BUILDPACK_VERSION}/pack-v${BUILDPACK_VERSION}-linux.tgz" | \
    tar -C /usr/local/bin --no-same-owner -xzv pack

# Create requirements file for Python dependencies
COPY requirements-simple.txt /tmp/requirements.txt

# Install Python dependencies for SLSA tools
RUN pip3 install --no-cache-dir --upgrade pip --break-system-packages && \
    pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

# Create jenkins user with proper permissions
RUN addgroup -g 1000 jenkins && \
    adduser -D -u 1000 -G jenkins jenkins

# Add jenkins to docker group for Docker operations
RUN addgroup -g 999 docker && \
    adduser jenkins docker || true

# Create workspace directory
RUN mkdir -p /home/jenkins/agent && \
    chown -R jenkins:jenkins /home/jenkins

# Set up environment for keyless signing
ENV COSIGN_EXPERIMENTAL=1
ENV SIGSTORE_NO_DEFAULT_TUF_ROOT=1

# Copy security scripts and utilities
COPY scripts/ /usr/local/bin/
RUN chmod +x /usr/local/bin/*.py /usr/local/bin/*.sh

# Verify all tool installations
RUN echo "=== Verifying tool installations ===" && \
    trivy --version && \
    cosign version && \
    slsa-verifier version && \
    syft version && \
    grype version && \
    pack version && \
    echo "=== All tools verified successfully ==="

# Switch to jenkins user
USER jenkins
WORKDIR /home/jenkins/agent

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD trivy --version && cosign version || exit 1

CMD ["/bin/bash", "-c", "cat"]