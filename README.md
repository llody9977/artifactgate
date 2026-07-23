# ArtifactGate: Enterprise Third-Party Container Admission Architecture

> [!NOTE]
> **Reference Implementation — Not a Multi-Tenant Security Platform**
> ArtifactGate is a reference architecture and implementation pattern for admitting third-party container images into enterprise infrastructure. Several controls require additional governance and infrastructure before production deployment.

ArtifactGate provides a zero-trust admission control architecture for third-party container images. It binds security evidence collection, Open Policy Agent (OPA) Policy-as-Code evaluation, Cosign keyless attestations, and deployment verification to immutable cryptographic artifact digests (`sha256:`).

---

## Why This Exists

Ingesting third-party container images directly into enterprise infrastructure creates substantial **business risk**:
- **Operational Disruption**: Unverified upstream updates or compromised container layers can introduce malicious code, causing service downtime.
- **Regulatory & Legal Exposure**: Unclassified copyleft licenses (GPL/AGPL) or unpatched CISA KEV vulnerabilities expose organizations to compliance fines and legal liability.
- **Tag Drift Outages**: Referencing mutable tags (`:latest`, `:v2`) causes silent environment drift where staging and production run different underlying code.

ArtifactGate solves these business risks by establishing a strict 4-plane admission architecture.

---

## Key Capabilities

- **Intake & Digest Resolution**: Resolves upstream references to immutable SHA-256 digests for `linux/amd64` architecture.
- **Multi-Dimensional Scanning**: Runs Trivy static vulnerability scanning, SPDX 2.3 SBOM generation, secret detection, license classification, and ClamAV malware screening.
- **Dynamic Observation**: Audits dynamic system call activity via kernel-level Tracee eBPF tracing and OWASP ZAP baseline web scans.
- **OPA Policy-as-Code Engine**: Evaluates normalized `evidence.json` against Rego policy modules in `policy/artifactgate/` with declarative data profiles in `policy/data/config.json`.
- **Machine-Readable Waiver Lifecycle**: Enforces structured OpenVEX / Waiver records (`waiver.json`) with mandatory risk owners, expiration dates, and active CVE coverage checks.
- **OIDC Keyless Attestations**: Keylessly signs and attaches Cosign attestations (SLSA provenance, SPDX SBOM, OpenVEX, and `promotiondecision` predicates) to promoted OCI images.
- **Deployment Admission Verification**: `install.sh` verifies Cosign signatures, SLSA provenance, OpenVEX documents, policy hashes, and 4-digest pairing before container initialization.
- **Continuous Post-Release Re-scanning**: Re-scans promoted images weekly on a cron schedule (`rescan.yml`) to detect vulnerability decay post-promotion.

---

## 4-Plane Admission Architecture

```text
               [ GOVERNANCE PLANE ]
   Policies · Exceptions · Approvals · Risk Owners
                         │
                         ▼
UNTRUSTED           ASSESSMENT            TRUSTED
SOURCE                 PLANE              ARTIFACT

Registry ──► Resolve ──► Evidence ──► OPA Decision ──► Promote + Attest
              digest      store             │                 │
                            │               v                 v
                            └────────► [REJECTED]     Controlled Registry
                                                              │
                                                              v
                                                       Admission Control
                                                              │
                                                              v
                                                           Runtime
                                                              │
                                                              v
                                                      Reassess / Revoke
```

---

## Decision Output Example

OPA policy evaluation generates structured decision predicates (`promotion-decision.json`):

```json
{
  "status": "MANUAL_REVIEW",
  "policy_version": "2026.07",
  "blocking_findings": 0,
  "review_findings": 2,
  "findings": [
    {
      "rule_id": "VULN-003",
      "category": "vulnerability",
      "severity": "review",
      "subject": "CVE-2026-4321",
      "message": "High vulnerability CVE-2026-4321 exceeds EPSS threshold (EPSS: 0.0450)",
      "remediation": "Review EPSS risk or submit active waiver"
    },
    {
      "rule_id": "RNT-002",
      "category": "runtime",
      "severity": "info",
      "subject": "runner_runtime_exemption",
      "message": "Task runner dynamic observation is explicitly exempted under policy rule runtime.runner.exemption",
      "remediation": "Assurance gap recorded in decision predicate"
    }
  ]
}
```

---

## Quick Start Guide

### 1. Prerequisites
Ensure Docker, Python 3.10+, Cosign, and OPA CLI are installed:
```bash
curl -sL -o /tmp/opa https://github.com/open-policy-agent/opa/releases/download/v1.18.2/opa_darwin_arm64 && chmod +x /tmp/opa
```

### 2. Run Policy Unit Tests
Verify Rego rules against test fixtures:
```bash
/tmp/opa test policy/artifactgate/ policy/data/ policy/tests/
```

### 3. Normalize Evidence & Evaluate OPA Policy
```bash
# Build normalized evidence.json from scan outputs
python3 .github/scripts/build_normalized_evidence.py sha256:appsrc123 sha256:runsrc123

# Evaluate OPA Policy-as-Code
python3 .github/scripts/evaluate_opa_policy.py evidence.json promotion-decision.json
```

### 4. Validate Deployment Admission
Verify promotion predicate and digest integrity before local installation:
```bash
python3 .github/scripts/validate_promotion_decision.py \
  --predicate promotion-decision.json \
  --expected-app-promoted-digest sha256:appsrc123 \
  --expected-runner-promoted-digest sha256:runsrc123 \
  --expected-repository llody9977/artifactgate
```

---

## Repository Map

```text
artifactgate/
├── .github/
│   ├── scripts/                # Evaluation, evidence normalized builder, & validation scripts
│   └── workflows/              # Image promotion, CI scanning, & scheduled re-scanning workflows
├── iac/
│   └── n8n/                    # Hardened Docker Compose manifests & install.sh installer script
├── policy/
│   ├── artifactgate/           # OPA Rego policy modules (source, evidence, vuln, lic, secrets, malware, runtime, exc, decision)
│   ├── data/                   # OPA configuration profiles (config.json)
│   ├── schemas/                # Canonical JSON Schemas (evidence.schema.json, decision.schema.json)
│   └── tests/                  # Rego unit test suite (opa test)
├── docs/                       # Detailed specifications & operational documentation
└── site/                       # Executive & security architect landing site (index.html)
```

---

## Security Boundaries & Limitations

- **Downstream Provenance Scope**: ArtifactGate attests downstream promotion provenance; it does not claim SLSA build levels for vendor images it did not compile.
- **Known Malware & Vulnerability Scope**: Scanners detect cataloged CVEs, KEV exploits, and ClamAV signatures. Zero-day threats require continuous re-scanning.
- **Runner Runtime Exemption**: Companion runner dynamic observation is explicitly exempted (`EXEMPTED`) under policy and recorded as an assurance gap.

---

## Documentation Sitemap

For complete technical specifications, review the modular documentation in `docs/`:

- 📋 [Requirements Specification](file:///Users/llody/Documents/artifactgate/docs/requirements.md)
- 🎯 [Threat Model & Business Risk Specification](file:///Users/llody/Documents/artifactgate/docs/threat-model.md)
- ⚙️ [Policy-as-Code & OPA Model Specification](file:///Users/llody/Documents/artifactgate/docs/policy-model.md)
- 📜 [Standards & Recognized Guidance Mapping](file:///Users/llody/Documents/artifactgate/docs/standards-mapping.md)
- 🔍 [Supply Chain Incident Case Studies](file:///Users/llody/Documents/artifactgate/docs/incident-case-studies.md)
- 🛡️ [Assurance Boundaries & Scope Limitations](file:///Users/llody/Documents/artifactgate/docs/assurance-boundary.md)
- 📊 [Implementation Status & Maturity Matrix](file:///Users/llody/Documents/artifactgate/docs/implementation-status.md)
- 🚀 [Production Deployment & Operations Guide](file:///Users/llody/Documents/artifactgate/docs/production-deployment.md)
