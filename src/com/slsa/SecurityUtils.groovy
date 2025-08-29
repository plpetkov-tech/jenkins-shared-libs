package com.slsa

/**
 * Security utility functions for SLSA pipelines
 */
class SecurityUtils {
    
    static def validateSeverityThreshold(String threshold) {
        def validThresholds = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        if (!validThresholds.contains(threshold.toUpperCase())) {
            throw new IllegalArgumentException("Invalid threshold: ${threshold}. Must be one of: ${validThresholds}")
        }
        return threshold.toUpperCase()
    }
    
    static def generateImageDigest(String registry, String imageName, String tag) {
        return "${registry}/${imageName}@sha256:${tag}"
    }
    
    static def createSLSAMetadata(Map config) {
        return [
            slsa_level: config.slsaLevel ?: "3",
            build_type: "jenkins-kubernetes",
            builder_id: "${config.jenkinsUrl}/slsa/v1",
            invocation_id: config.buildNumber ?: "",
            timestamp: new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'")
        ]
    }
    
    static def sanitizeImageName(String imageName) {
        // Remove invalid characters and ensure lowercase
        return imageName.toLowerCase()
                       .replaceAll('[^a-z0-9._/-]', '-')
                       .replaceAll('-+', '-')
                       .replaceAll('^-|-$', '')
    }
    
    static def extractImageComponents(String fullImageName) {
        def parts = fullImageName.split('/')
        if (parts.length < 2) {
            throw new IllegalArgumentException("Image name must include registry/username: ${fullImageName}")
        }
        
        def tagSplit = parts[-1].split(':')
        def imageName = parts[0..-2].join('/') + '/' + tagSplit[0]
        def tag = tagSplit.length > 1 ? tagSplit[1] : 'latest'
        
        return [
            fullName: fullImageName,
            name: imageName,
            tag: tag,
            repository: parts[-1].split(':')[0],
            namespace: parts[0..-2].join('/')
        ]
    }
}