#!/usr/bin/env python3
import sys
import json
import datetime
import hashlib

def main():
    if len(sys.argv) < 2:
        print("Usage: generate_vex.py <trivy-report.json>")
        sys.exit(1)
        
    try:
        with open(sys.argv[1], 'r') as f:
            report = json.load(f)
    except Exception as e:
        print(f"Error reading report: {e}")
        sys.exit(1)
        
    generated = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    report_digest = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
    metadata = report.get("Metadata", {})
    app_product = f"pkg:oci/n8n@{metadata.get('imageDigest', 'unknown')}?repository_url=ghcr.io/llody9977/artifactgate/n8n-trusted"
    runner_product = f"pkg:oci/n8n-runners@{metadata.get('runnerDigest', 'unknown')}?repository_url=ghcr.io/llody9977/artifactgate/n8n-runners-trusted"
    vex = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://github.com/llody9977/artifactgate/vex/{report_digest}",
        "author": "artifactgate-pipeline",
        "timestamp": generated,
        "version": 1,
        "statements": []
    }
    
    results = report.get('Results', [])
    for res in results:
        product = runner_product if str(res.get("Target", "")).startswith("n8n-runners:") else app_product
        vulns = res.get('Vulnerabilities', [])
        for vul in vulns:
            vuln_id = vul.get("VulnerabilityID")
            pkg_name = vul.get("PkgName")
            gate_decision = vul.get("GateDecision")
            reachable = vul.get("Reachability", "Unknown")
            
            if not vuln_id:
                continue
            if reachable in {"Not observed", "No"}:
                statement = {
                    "vulnerability": {"name": vuln_id},
                    "products": [{"@id": product}],
                    "status": "under_investigation",
                    "impact_statement": f"Files mapped to {pkg_name} were not observed in the bounded Tracee smoke test. This is supporting evidence only and does not prove that vulnerable code is unreachable."
                }
                vex["statements"].append(statement)
            elif gate_decision == "AUTO_ALLOWED":
                statement = {
                    "vulnerability": {"name": vuln_id},
                    "products": [{"@id": product}],
                    "status": "under_investigation",
                    "impact_statement": f"{pkg_name} auto-promoted since it lacks KEV evidence, high EPSS, or aged exposure."
                }
                vex["statements"].append(statement)
                
    print(json.dumps(vex, indent=2))

if __name__ == "__main__":
    main()
