# Policy-as-Code & Decision Model Specification

ArtifactGate uses Open Policy Agent (OPA) as a centralized Policy-as-Code engine. All security scanners collect evidence into a normalized `evidence.json` object, while OPA evaluates that evidence against versioned Rego policies.

---

## 1. Policy Principles

1. **Scanners Collect Evidence; OPA Decides Acceptability**: Scanners (Trivy, ClamAV, ZAP, Tracee) do not make promotion decisions. They generate evidence that OPA evaluates.
2. **Normalized Input Contract**: Evidence is converted into a canonical `evidence.json` format before evaluation.
3. **Structured Machine-Readable Output**: OPA returns detailed decision objects containing status verdicts, policy versions, blocking counts, and granular rule findings.

---

## 2. Policy Rule Domains

ArtifactGate organizes Rego rules into 10 explicit policy domains:

| Domain ID | Category Name | Description | Policy Path |
| :--- | :--- | :--- | :--- |
| **POL-SRC** | Source & Supplier | Verifies upstream image allowlists and vendor source paths | `policy/artifactgate/source.rego` |
| **POL-ID** | Artifact Identity | Binds SHA-256 digests and platform architecture (`linux/amd64`) | `policy/artifactgate/source.rego` |
| **POL-EVD** | Evidence Completeness | Verifies required scanner completion flags and policy hash integrity | `policy/artifactgate/evidence.rego` |
| **POL-VULN** | Vulnerabilities | Evaluates CVE severities, CISA KEV status, EPSS scores, and age | `policy/artifactgate/vulnerabilities.rego` |
| **POL-LIC** | Licensing | Evaluates copyleft, allowed, review-required, and prohibited licenses | `policy/artifactgate/licenses.rego` |
| **POL-SEC** | Secrets & Malware | Blocks embedded credentials and ClamAV malware signatures | `policy/artifactgate/secrets.rego` & `malware.rego` |
| **POL-PROV** | Provenance | Verifies upstream publisher signatures and SLSA attestations | `policy/artifactgate/evidence.rego` |
| **POL-RUN** | Runtime Posture | Evaluates application Tracee eBPF tracing and runner exemptions | `policy/artifactgate/runtime.rego` |
| **POL-EXC** | Risk Exceptions | Validates OpenVEX and waiver expirations, accepted CVEs, and approvers | `policy/artifactgate/exceptions.rego` |
| **POL-DEC** | Admission Decision | Root aggregator mapping rule findings to final status verdict | `policy/artifactgate/decision.rego` |

---

## 3. Standardized Decision Verdicts

OPA policy evaluation produces one of seven standard outcome verdicts:

- `APPROVED`: Zero blocking or review findings. Eligible for immediate auto-promotion.
- `APPROVED_WITH_EXCEPTION`: Zero blocking findings; active, unexpired waiver covers identified vulnerabilities.
- `MANUAL_REVIEW`: Zero blocking findings, but review-required items exist (e.g. EPSS threshold exceedance, runner exemption).
- `REJECTED`: One or more blocking policy violations exist (e.g. active KEV exploit, prohibited license, malware).
- `EXPIRED`: Previously valid exception waiver has exceeded its expiration date.
- `REVOKED`: Artifact was previously approved but has been revoked due to new KEV exploits during continuous re-scanning.
- `ERROR`: Pipeline error, missing evidence, or malformed JSON input prevented policy evaluation.

---

## 4. Standard Decision Payload Example

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
