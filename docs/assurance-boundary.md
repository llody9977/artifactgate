# Assurance Boundaries & Scope Limitations

This document explicitly defines what ArtifactGate assures, what assumptions it relies upon, and what operational capabilities remain outside its security scope.

---

## 1. What ArtifactGate Assures

When ArtifactGate promotes and approves a container image pair, it provides machine-readable, cryptographic proof (`promotiondecision` attestation) that:

1. **Digest Identity & Platform**: The assessed artifact is bound to exact OCI SHA-256 digests for the `linux/amd64` platform architecture.
2. **Evidence Completeness**: All configured static scanners (Trivy vulnerability, secret, license, ClamAV malware) and dynamic observations (Tracee eBPF) completed successfully without silent errors.
3. **Declarative Policy Compliance**: The normalized evidence evaluated against versioned OPA Rego policies (`policy/artifactgate/`) without triggering un-waived blocking rules (CISA KEV exploits, Critical CVEs, prohibited copyleft licenses).
4. **Waiver Binding**: Any accepted vulnerabilities (`APPROVED_WITH_EXCEPTION`) are covered by active, unexpired OpenVEX waiver records with accountable risk owners and expiration dates.
5. **Signed Downstream Attestations**: Provenance, SPDX SBOMs, OpenVEX records, and promotion decision predicates were keylessly signed using GitHub Actions OIDC identity tokens.

---

## 2. Unverified Assumptions & Out-of-Scope Items

ArtifactGate explicitly **does not claim or guarantee**:

- **Upstream Build Parity or SLSA Levels**: ArtifactGate does not claim a SLSA build level for third-party vendor images that it did not build. It attests downstream promotion provenance only.
- **Zero-Day Vulnerability Exclusion**: Static scanners can only identify vulnerabilities listed in public CVE, KEV, and advisory databases. Zero-day exploits remain unflagged until cataloged.
- **Custom Obfuscated Logic Bombs**: Bounded dynamic observation (Tracee eBPF) monitors standard system calls during quarantine execution. Advanced evasive malware that delays execution or detects sandbox environments will bypass observation.
- **Complete Upstream Publisher Identity**: Vendor signature verification is dependent on upstream publishers providing Sigstore/Cosign signatures. When vendors do not sign builds, upstream identity is recorded as unverified.
- **Registry Retention & High Availability**: Image availability and registry storage lifecycle management in GHCR or private registries remain external infrastructure responsibilities.
- **Host Kernel Vulnerabilities**: ArtifactGate assesses container image layers and application configuration. It does not secure underlying host Linux kernels, Docker daemon configurations, or physical hardware.
