package com.slsa

/**
 * SBOM generation utilities for multiple formats and sources
 */
class SBOMGenerator {
    
    def script
    
    SBOMGenerator(script) {
        this.script = script
    }
    
    def generateApplicationSBOM(String projectPath, String format = "cyclonedx-json") {
        def outputFile = "sbom-application.${getFormatExtension(format)}"
        
        script.sh """
            cd ${projectPath}
            
            # Try different SBOM generators based on project type
            if [ -f "poetry.lock" ]; then
                echo "Detected Poetry project, generating Python SBOM..."
                cyclonedx-py poetry --output-format ${format} --output-file ${outputFile}
            elif [ -f "requirements.txt" ]; then
                echo "Detected pip requirements, generating Python SBOM..."
                cyclonedx-py requirements --output-format ${format} --output-file ${outputFile} requirements.txt
            elif [ -f "package-lock.json" ]; then
                echo "Detected npm project, generating Node.js SBOM..."
                cyclonedx-npm --output-format ${format} --output-file ${outputFile}
            elif [ -f "pom.xml" ]; then
                echo "Detected Maven project, generating Java SBOM..."
                cyclonedx-maven --output-format ${format} --output-file ${outputFile}
            elif [ -f "build.gradle" ] || [ -f "build.gradle.kts" ]; then
                echo "Detected Gradle project, generating Java SBOM..."
                cyclonedx-gradle --output-format ${format} --output-file ${outputFile}
            elif [ -f "go.mod" ]; then
                echo "Detected Go project, generating Go SBOM..."
                cyclonedx-gomod --output-format ${format} --output-file ${outputFile}
            else
                echo "No supported project type detected, creating minimal SBOM..."
                createMinimalSBOM ${outputFile} ${format}
            fi
        """
        
        return outputFile
    }
    
    def generateContainerSBOM(String image, String format = "cyclonedx-json") {
        def outputFile = "sbom-container.${getFormatExtension(format)}"
        
        script.sh """
            echo "Generating container SBOM for ${image}..."
            syft ${image} --output ${format}=${outputFile}
        """
        
        return outputFile
    }
    
    def consolidateSBOMs(List sbomFiles, String outputFile, Map metadata = [:]) {
        script.sh """
            echo "Consolidating SBOMs: ${sbomFiles.join(', ')}"
            
            # Create consolidated SBOM with SLSA metadata
            python3 << 'EOF'
import json
import uuid
from datetime import datetime

consolidated = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "version": 1,
    "metadata": {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tools": [
            {
                "vendor": "Jenkins SLSA Pipeline",
                "name": "SBOM Consolidator",
                "version": "1.0.0"
            }
        ],
        "properties": [
            {"name": "slsa:build_type", "value": "${metadata.buildType ?: 'jenkins-kubernetes'}"},
            {"name": "slsa:builder_id", "value": "${metadata.builderId ?: ''}"},
            {"name": "slsa:build_id", "value": "${metadata.buildId ?: ''}"},
            {"name": "slsa:level", "value": "${metadata.slsaLevel ?: '3'}"}
        ]
    },
    "components": []
}

# Merge all SBOM components
sbom_files = "${sbomFiles.join(' ')}"
for sbom_file in sbom_files.split():
    try:
        with open(sbom_file.strip(), 'r') as f:
            sbom = json.load(f)
            if 'components' in sbom:
                consolidated['components'].extend(sbom['components'])
    except Exception as e:
        print(f"Warning: Could not process {sbom_file}: {e}")

# Remove duplicates based on purl
seen_purls = set()
unique_components = []
for component in consolidated['components']:
    purl = component.get('purl', component.get('name', 'unknown'))
    if purl not in seen_purls:
        seen_purls.add(purl)
        unique_components.append(component)

consolidated['components'] = unique_components

# Write consolidated SBOM
with open('${outputFile}', 'w') as f:
    json.dump(consolidated, f, indent=2)

print(f"Consolidated SBOM with {len(unique_components)} unique components")
EOF
        """
        
        return outputFile
    }
    
    def validateSBOM(String sbomFile, String format = "cyclonedx-json") {
        def isValid = script.sh(
            script: """
                if [ "${format}" = "cyclonedx-json" ]; then
                    # Validate CycloneDX format
                    python3 -c "
import json
try:
    with open('${sbomFile}', 'r') as f:
        sbom = json.load(f)
    required_fields = ['bomFormat', 'specVersion', 'components']
    for field in required_fields:
        if field not in sbom:
            exit(1)
    print('SBOM validation passed')
    exit(0)
except Exception as e:
    print(f'SBOM validation failed: {e}')
    exit(1)
"
                elif [ "${format}" = "spdx-json" ]; then
                    # Validate SPDX format
                    python3 -c "
import json
try:
    with open('${sbomFile}', 'r') as f:
        sbom = json.load(f)
    if 'SPDXID' not in sbom or 'packages' not in sbom:
        exit(1)
    print('SPDX validation passed')
    exit(0)
except Exception as e:
    print(f'SPDX validation failed: {e}')
    exit(1)
"
                else
                    echo "Unknown format: ${format}"
                    exit(1)
                fi
            """,
            returnStatus: true
        ) == 0
        
        if (!isValid) {
            script.error("SBOM validation failed for ${sbomFile}")
        }
        
        return isValid
    }
    
    private def getFormatExtension(String format) {
        switch (format.toLowerCase()) {
            case "cyclonedx-json":
            case "cyclonedx":
                return "json"
            case "spdx-json":
            case "spdx":
                return "spdx.json"
            case "cyclonedx-xml":
                return "xml"
            default:
                return "json"
        }
    }
    
    private def createMinimalSBOM(String outputFile, String format) {
        script.sh """
            cat > ${outputFile} << 'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:$(uuidgen)",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tools": [
      {
        "vendor": "Jenkins SLSA Pipeline",
        "name": "Minimal SBOM Generator",
        "version": "1.0.0"
      }
    ]
  },
  "components": []
}
EOF
        """
    }
}