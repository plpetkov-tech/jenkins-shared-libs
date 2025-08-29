package com.slsa

/**
 * HashiCorp Vault client for SLSA pipeline secrets management
 */
class VaultClient {
    
    def script
    def vaultAddr
    
    VaultClient(script, String vaultAddr) {
        this.script = script
        this.vaultAddr = vaultAddr
    }
    
    def authenticateWithJWT(String role, String jwt) {
        def response = script.sh(
            script: """
                vault auth -method=jwt \\
                    -path=jwt \\
                    role=${role} \\
                    jwt=${jwt} \\
                    -format=json
            """,
            returnStdout: true
        ).trim()
        
        def auth = script.readJSON(text: response)
        return auth.auth.client_token
    }
    
    def readSecret(String path, String token) {
        script.withEnv(["VAULT_TOKEN=${token}"]) {
            def response = script.sh(
                script: """
                    vault kv get -format=json ${path}
                """,
                returnStdout: true
            ).trim()
            
            def secret = script.readJSON(text: response)
            return secret.data.data
        }
    }
    
    def writeSecret(String path, Map data, String token) {
        def dataArgs = data.collect { k, v -> "${k}=${v}" }.join(' ')
        
        script.withEnv(["VAULT_TOKEN=${token}"]) {
            script.sh """
                vault kv put ${path} ${dataArgs}
            """
        }
    }
    
    def storeSLSAArtifact(String buildId, String artifactType, String content, String token) {
        def path = "slsa-artifacts/${buildId}/${artifactType}"
        writeSecret(path, [content: content, timestamp: new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'")], token)
    }
    
    def retrieveSLSAArtifact(String buildId, String artifactType, String token) {
        def path = "slsa-artifacts/${buildId}/${artifactType}"
        try {
            def data = readSecret(path, token)
            return data.content
        } catch (Exception e) {
            script.echo "Warning: Could not retrieve SLSA artifact ${path}: ${e.message}"
            return null
        }
    }
    
    def listSLSAArtifacts(String buildId, String token) {
        script.withEnv(["VAULT_TOKEN=${token}"]) {
            try {
                def response = script.sh(
                    script: """
                        vault kv metadata list slsa-artifacts/${buildId}/ -format=json
                    """,
                    returnStdout: true
                ).trim()
                
                def result = script.readJSON(text: response)
                return result.data.keys
            } catch (Exception e) {
                script.echo "Warning: Could not list SLSA artifacts for build ${buildId}: ${e.message}"
                return []
            }
        }
    }
}