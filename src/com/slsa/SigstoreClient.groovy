package com.slsa

/**
 * Sigstore client utilities for keyless signing and verification
 */
class SigstoreClient {
    
    def script
    def config
    
    SigstoreClient(script, Map config) {
        this.script = script
        this.config = config
    }
    
    def signImage(String image, String oidcToken) {
        script.sh """
            # Export OIDC token for keyless signing
            export COSIGN_EXPERIMENTAL=1
            export SIGSTORE_ID_TOKEN="${oidcToken}"
            
            # Sign the container image
            cosign sign --yes \\
                --fulcio-url=${config.fulcioUrl} \\
                --rekor-url=${config.rekorUrl} \\
                ${image}
        """
    }
    
    def signBlob(String filePath, String outputSig, String oidcToken) {
        script.sh """
            export COSIGN_EXPERIMENTAL=1
            export SIGSTORE_ID_TOKEN="${oidcToken}"
            
            cosign sign-blob --yes \\
                --fulcio-url=${config.fulcioUrl} \\
                --rekor-url=${config.rekorUrl} \\
                --output-signature=${outputSig} \\
                ${filePath}
        """
    }
    
    def attachAttestation(String image, String attestationPath, String oidcToken) {
        script.sh """
            export COSIGN_EXPERIMENTAL=1
            export SIGSTORE_ID_TOKEN="${oidcToken}"
            
            cosign attest --yes \\
                --fulcio-url=${config.fulcioUrl} \\
                --rekor-url=${config.rekorUrl} \\
                --predicate=${attestationPath} \\
                --type=slsaprovenance \\
                ${image}
        """
    }
    
    def verifyImage(String image) {
        return script.sh(
            script: """
                cosign verify \\
                    --certificate-oidc-issuer=${config.oidcIssuer} \\
                    --certificate-identity-regexp=".*" \\
                    --rekor-url=${config.rekorUrl} \\
                    ${image}
            """,
            returnStatus: true
        ) == 0
    }
    
    def verifyAttestation(String image, String policyPath = null) {
        def policyFlag = policyPath ? "--policy ${policyPath}" : ""
        
        return script.sh(
            script: """
                cosign verify-attestation \\
                    --certificate-oidc-issuer=${config.oidcIssuer} \\
                    --certificate-identity-regexp=".*" \\
                    --rekor-url=${config.rekorUrl} \\
                    ${policyFlag} \\
                    ${image}
            """,
            returnStatus: true
        ) == 0
    }
    
    def downloadAttestation(String image, String outputFile) {
        script.sh """
            cosign download attestation \\
                --predicate-type=slsaprovenance \\
                ${image} > ${outputFile}
        """
    }
}