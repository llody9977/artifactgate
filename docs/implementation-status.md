# Implementation Status & Operational Maturity Matrix

This document provides an authoritative control status inventory and an operational maturity evaluation for ArtifactGate.

---

## 1. Control Enforcement Matrix

| Control Name | Implementation Status | Enforcement Scope | Current Capability & Production Gap |
| :--- | :--- | :--- | :--- |
| **Source Allowlist** | Implemented | Blocking | Enforces upstream repository allowlists (`n8nio/n8n`, `n8nio/runners`) in OPA `source.rego` |
| **Digest Pinning** | Implemented | Blocking | Binds intake and promotion strictly to immutable SHA-256 digests for `linux/amd64` |
| **Vulnerability Policy** | Implemented | Blocking / Review | Enforces CISA KEV catalog blocking, EPSS thresholds, and max CVE age via OPA `vulnerabilities.rego` |
| **Secret Scanning** | Implemented | Blocking | Scans container layers via Trivy and blocks embedded credentials via OPA `secrets.rego` |
| **Malware Scanning** | Implemented | Blocking | Scans container payloads via ClamAV and blocks signatures via OPA `malware.rego` |
| **Licence Classification** | Implemented | Advisory / Review | Classifies licenses and flags prohibited copyleft licenses via OPA `licenses.rego` |
| **Application Runtime Observation** | Implemented | Blocking | Audits system calls and library loads during quarantine execution via Tracee eBPF |
| **Runner Runtime Observation** | Exempted | Advisory (`EXEMPTED`) | Dynamic observation of task runner containers is explicitly exempted under policy rule `runtime.runner.exemption` |
| **OWASP ZAP Web Scan** | Implemented | Limited Scope | Unauthenticated baseline web scan providing passive web interface exposure observations |
| **Upstream Publisher Signature** | Implemented | Warning | Evaluates vendor signatures when present; recorded as accepted identity gap when missing |
| **Promotion Attestation** | Implemented | Blocking at Installer | Keylessly signs and attaches `promotiondecision` predicates to promoted images in GHCR |
| **Deployment Admission Verification** | Implemented | Blocking (`install.sh`) | `install.sh` verifies Cosign signatures, SLSA provenance, OpenVEX, and 4-digest pairing before startup |
| **Kubernetes Admission Controller** | Not Implemented | None | Production adoption requires a Kubernetes admission controller (e.g. Kyverno / Sigstore policy-controller) |
| **Scheduled Re-scanning** | Implemented | Issue Creation | `rescan.yml` re-scans promoted images weekly; creates GitHub issues on vulnerability decay |
| **Automated Revocation** | Not Implemented | None | Automated runtime image eviction or registry tombstoning is not implemented |

---

## 2. Operational Maturity Model (Levels 0–5)

- **Level 0 — Basic Visibility**: Scan container images, generate SBOMs, and retain static scan reports.
- **Level 1 — Controlled Decision**: Bind assessments to immutable digests, evaluate standardized policies, generate machine-readable decision records, and enforce expiring waivers.
- **Level 2 — Controlled Promotion**: Separate trusted registry paths, keylessly sign promotion decision attestations, enforce CI pipeline protection, and maintain segregation of duties.
- **Level 3 — Deployment Admission Control**: Enforce admission policies at container runtime engines (Kubernetes admission controllers / Docker engines), preventing bypass of CI/CD decisions.
- **Level 4 — Continuous Assurance & Revocation**: Execute continuous automated re-scanning against running workloads, enforce automated exception revocation, and maintain live running workload asset inventories.
- **Level 5 — Organizational Policy Service**: Distribute centrally managed, versioned OPA policy bundles across multi-cloud environments with centralized reporting, risk dashboards, and compliance SLOs.

---

## 3. ArtifactGate Reference Implementation Maturity Self-Evaluation

| Maturity Dimension | Current ArtifactGate Level | Assessment Summary |
| :--- | :--- | :--- |
| **Evidence Collection** | **Level 2** | Comprehensive static scanning (Trivy, ClamAV), SBOM generation (SPDX 2.3), and Tracee eBPF dynamic observation. |
| **Policy Engine** | **Level 2** | Centralized OPA Rego engine (`policy/artifactgate/`) evaluating normalized `evidence.json` with versioned data profiles. |
| **Promotion Controls** | **Level 2** | Protected GHCR registry path copy, keyless Cosign attestation signing, and 4-digest binding. |
| **Deployment Enforcement** | **Level 1–2** | Hardened `install.sh` installer verifies Cosign signatures, SLSA provenance, and decision predicates. (K8s admission controller is Level 3). |
| **Continuous Assurance** | **Level 2** | Weekly cron re-scanning (`rescan.yml`) with automated issue creation on security decay. |
| **Organizational Governance**| **Level 1** | Standard Rego policy templates, versioned `config.json`, and machine-readable OpenVEX waiver contracts. |
