// Simple SLSA Level 3 Pipeline Example
@Library('jenkins-shared-libs') _

pipeline {
    agent none
    
    stages {
        stage('SLSA Security Build') {
            steps {
                script {
                    // Minimal configuration - uses library defaults
                    slsaSecurityPipeline([
                        imageName: 'plpetkov-tech/simple-app',
                        imageTag: env.BUILD_NUMBER
                    ])
                }
            }
        }
    }
}