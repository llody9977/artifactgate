# Artifact Admission Requirements Specification

This document defines the functional, operational, and security requirements for an enterprise container artifact admission control system.

---

## 1. Functional Requirements

An enterprise third-party artifact admission system must:

1. **Artifact & Platform Binding**: Unambiguously identify the target OCI artifact by immutable cryptographic digest (SHA-256) and explicit architecture platform (`linux/amd64`).
2. **Source & Version Governance**: Enforce strict upstream source image allowlists and version intake policies to restrict unauthorized upstream software ingestion.
3. **Multi-Dimensional Evidence Collection**: Collect standardized security evidence across vulnerability scans (Trivy), secret scans, license classifications, SBOM component inventories (SPDX/CycloneDX), and known-signature malware screening (ClamAV).
4. **Evidence Integrity & Freshness Validation**: Verify evidence completeness, freshness, and cryptographic policy hash alignment before evaluation, failing closed if scans are missing or malformed.
5. **Declarative Policy Evaluation**: Evaluate normalized evidence using centrally managed, versioned, and unit-tested Policy-as-Code (Open Policy Agent).
6. **Controlled Exception Lifecycle**: Support machine-readable, time-bounded, and owner-attributed risk exceptions (OpenVEX / Waiver JSON) with explicit compensating controls.
7. **Explainable Decision Output**: Generate machine-readable, structured decision artifacts containing granular rule IDs, severities, evidence references, and remediation guidance.
8. **Controlled Registry Promotion**: Promote only approved artifact pairs to protected internal registry paths upon successful policy evaluation.
9. **Attestation & Cryptographic Binding**: Keylessly sign and attach promotion attestations, SBOM metadata, OpenVEX records, and promotion decision predicates to promoted OCI digests using OIDC identities.
10. **Deployment Admission Enforcement**: Re-evaluate and enforce signed decision predicates and digest identities at deployment time (e.g. installer scripts or Kubernetes admission controllers).
11. **Continuous Risk Re-assessment**: Automatically re-scan promoted and deployed artifacts on a recurring schedule to identify post-release vulnerability decay and expired exceptions.
12. **Revocation & Replacement**: Provide workflows for emergency artifact revocation and automated issue creation when risk thresholds are exceeded post-promotion.

---

## 2. Risk Management & Security Requirements

To protect organizations against business risk and supply chain compromise, the admission system must:

- **Fail-Closed Security Posture**: Default to rejection whenever evidence is incomplete, missing, malformed, or unverified.
- **Untrusted Environment Isolation**: Execute untrusted container workloads and dynamic scans in bounded, isolated sandboxes with network restrictions.
- **Least-Privilege Authorization**: Restrict CI/CD pipeline credentials and OIDC signing identities to minimum necessary permissions.
- **Separation of Duties**: Isolate policy ownership (security engineering) from workload requestors (application teams) to prevent self-approval.
- **Immutable Audit Records**: Retain signed, tamper-evident attestation records for all promotion decisions.
- **Protection Against Tag Drift**: Bind all security decisions strictly to immutable SHA-256 digests, eliminating tag mutation vulnerabilities.
- **Policy Verification**: Verify policy modifications via unit tests (`opa test`) in CI before merging into production policy bundles.
