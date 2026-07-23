# Standards & Recognized Guidance Mapping

ArtifactGate's controls are **informed by** recognized industry standards and security frameworks. ArtifactGate is a reference implementation architecture and does not claim official certification against any framework.

---

## Recognized Guidance Mapping Matrix

| Framework / Standard | Focus Area | How It Informs ArtifactGate | ArtifactGate Control Implementation |
| :--- | :--- | :--- | :--- |
| **NIST SP 800-161 Rev. 1** | Cybersecurity Supply Chain Risk Management (C-SCRM) | Informs third-party supplier risk management and ongoing component oversight | Upstream source allowlists, digest pinning, and weekly continuous re-scanning |
| **NIST SP 800-190** | Application Container Security Guide | Informs container image scanning, registry protection, and runtime monitoring | Layer-by-layer vulnerability scanning, secret detection, and Tracee eBPF syscall auditing |
| **NIST SP 800-218 (SSDF)** | Secure Software Development Framework | Informs secure component verification and third-party software ingestion controls | SPDX SBOM verification, OpenVEX exception handling, and OPA Policy-as-Code gating |
| **NIST SP 800-204D** | Software Supply Chain Controls in CI/CD | Informs pipeline security posture and build integrity controls | GitHub Actions environment protection, job least-privilege permissions, and commit SHA pinning |
| **SLSA (Supply-chain Levels for Software Artifacts)** | Software Build Provenance & Build Trust | Informs downstream promotion attestation structure and build provenance models | Uses SLSA concepts to structure downstream promotion attestations (does not claim SLSA build levels for vendor images) |
| **Sigstore / Cosign** | Cryptographic Identity & Attestation Signing | Informs identity-bound keyless signing and attestation verification | Cosign keyless OIDC signing of SLSA provenance, SBOM declarations, OpenVEX documents, and decision predicates |
| **SPDX / CycloneDX** | Standardized Software Bill of Materials | Informs machine-readable component inventory format specifications | Trivy/Syft SPDX 2.3 SBOM generation and downstream attestation binding |
| **OpenVEX** | Vulnerability Exploitability eXchange | Informs machine-readable vulnerability status communication and justification | Structured OpenVEX document generation and waiver-to-CVE validation in `validate_vex.py` |
| **CISA KEV Catalog** | Known Exploited Vulnerabilities Catalog | Informs active threat prioritization and mandatory vulnerability blocking | Real-time CISA KEV catalog lookup with fail-closed blocking for active exploits |
| **FIRST EPSS** | Exploit Prediction Scoring System | Informs probability-based vulnerability prioritization and review thresholds | Real-time EPSS score enrichment with explicit review threshold bands (High $\ge$ 2.0%, Critical $\ge$ 10.0%) |
| **Open Policy Agent (OPA)** | Policy-as-Code Engine | Informs declarative, centralized policy evaluation and decision standardizing | Rego policy modules in `policy/artifactgate/` evaluating normalized `evidence.json` |
| **CIS Benchmarks** | Container & Kubernetes Security Benchmarks | Informs container runtime hardening and deployment configuration posture | Non-root container execution, read-only root filesystem, and dropped Linux capabilities in Compose/K8s |
