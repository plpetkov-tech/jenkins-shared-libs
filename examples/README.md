# Jenkins Shared Library Examples

This directory contains example pipeline configurations for using the SLSA Level 3 Security Pipeline shared library.

## Quick Start

1. **Configure your Jenkins instance** to use this shared library:
   - Go to `Manage Jenkins` → `Configure System`
   - Under `Global Pipeline Libraries`, add a new library
   - Name: `jenkins-shared-libs`
   - Default version: `main`
   - Retrieval method: `Modern SCM`
   - Source Code Management: Git
   - Repository URL: `https://github.com/plpetkov-tech/jenkins-shared-libs.git`

2. **Use in your Jenkinsfile**:
   ```groovy
   @Library('jenkins-shared-libs') _
   
   pipeline {
       agent none
       stages {
           stage('SLSA Security Build') {
               steps {
                   script {
                       slsaSecurityPipeline([
                           imageName: 'your-org/your-app',
                           imageTag: env.BUILD_NUMBER
                       ])
                   }
               }
           }
       }
   }
   ```

## Examples

### [simple-pipeline.groovy](./simple-pipeline.groovy)
Minimal configuration using library defaults. Perfect for getting started.

**Features:**
- Uses all library defaults
- SLSA Level 3 compliance
- Keyless signing with Keycloak OIDC
- Build-time SBOM generation
- Container vulnerability scanning

### [Jenkinsfile.example](./Jenkinsfile.example)
Full-featured example with all configuration options and parameters.

**Features:**
- Parameterized build with user choices
- Multi-platform builds (linux/amd64, linux/arm64)
- Configurable SLSA level
- Optional VEX analysis
- Security report publishing
- Artifact archiving

## Configuration Options

### Required Parameters
- `imageName`: Container image name (include username/org prefix, e.g., 'plpetkov-tech/my-app')
- `imageTag`: Container image tag (e.g., 'latest', env.BUILD_NUMBER)

### Optional Parameters
- `registry`: Container registry (default: 'ghcr.io')
- `slsaLevel`: SLSA compliance level (default: '3')
- `enableVexAnalysis`: Enable runtime VEX analysis (default: false)
- `platforms`: Build platforms (default: ['linux/amd64', 'linux/arm64'])

### Security Configuration
```groovy
security: [
    vulnerabilityThreshold: 'HIGH',     // CRITICAL, HIGH, MEDIUM, LOW
    failOnCritical: true,               // Fail build on critical vulnerabilities
    enableSBOM: true,                   // Generate SBOM
    enableVEX: false                    // Generate VEX documents
]
```

### Build Configuration
```groovy
build: [
    dockerfile: './Dockerfile',         // Path to Dockerfile
    context: '.',                      // Build context
    buildArgs: [:]                     // Build arguments map
]
```

### Attestation Configuration
```groovy
attestation: [
    enableProvenance: true,            // Generate SLSA provenance
    enableSBOM: true,                  // Generate SBOM attestation
    enableVEX: false,                  // Generate VEX attestation
    keyless: true                      // Use keyless signing (Keycloak OIDC)
]
```

## Pipeline Outputs

The pipeline generates the following artifacts in the `slsa-artifacts/` directory:

- **SBOM**: `sbom.json` - Software Bill of Materials
- **Provenance**: `provenance.json` - SLSA build provenance
- **VEX**: `vex.json` - Vulnerability Exploitability Exchange (if enabled)
- **Reports**: `reports/security-report.html` - Security analysis report
- **Signatures**: Various `.sig` and `.att` files for verification

## Prerequisites

1. **Jenkins Configuration**: 
   - Jenkins instance with Kubernetes plugin
   - Access to Kubernetes cluster with proper RBAC
   - Configured shared library as described above

2. **Infrastructure Services**:
   - Keycloak OIDC provider at `https://keycloak.kubectl.shop/realms/ci`
   - Fulcio certificate authority at `https://fulcio.kubectl.shop`
   - Rekor transparency log at `https://rekor.kubectl.shop`
   - HashiCorp Vault at `https://vault.kubectl.shop`

3. **Container Registry**:
   - Access to `ghcr.io` (or configured alternative)
   - Proper authentication configured in Jenkins

## Troubleshooting

### Common Issues

1. **Pod Template Not Found**: Ensure the shared library is properly configured and accessible.

2. **Registry Authentication**: Check Jenkins credentials for container registry access.

3. **Sigstore Services**: Verify Keycloak, Fulcio, and Rekor services are accessible from Jenkins agents.

4. **Resource Limits**: The security pipeline requires significant resources. Ensure your Kubernetes cluster has sufficient capacity.

### Debug Mode
Enable debug logging by setting environment variable:
```groovy
environment {
    JENKINS_DEBUG = 'true'
}
```

## Support

For issues and questions:
- Check Jenkins build logs
- Review security reports in `slsa-artifacts/reports/`
- Verify infrastructure services are accessible
- Consult the main library documentation at [https://github.com/plpetkov-tech/jenkins-shared-libs](https://github.com/plpetkov-tech/jenkins-shared-libs)