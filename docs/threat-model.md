# Threat Model & Business Risk Specification

This document details the threat model, business risks, and attack vectors associated with ingesting third-party container images into enterprise infrastructure.

---

## 1. Executive Business Risk Framing

Ingesting third-party container images directly into production infrastructure introduces significant **business risk**:

1. **Operational Disruption & Unplanned Outages**: Unverified upstream updates or compromised container layers can introduce malicious code, causing service outages and customer downtime.
2. **Regulatory Non-Compliance**: Ingesting software with unclassified copyleft licenses (GPL/AGPL) or unpatched CISA KEV vulnerabilities exposes organizations to legal liability and regulatory fines.
3. **Brand Erosion & Financial Loss**: Hardcoded credentials or backdoored components can lead to data breaches, unauthorized intellectual property access, and severe reputational damage.
4. **Tag Drift & Deployment Mismatch**: Deploying container tags rather than immutable digests causes silent environment drift where staging and production run different underlying code.

---

## 2. Attack Vectors & Mitigation Matrix

| Threat Category | Attack Vector | Business Impact | ArtifactGate Control | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| **1. Unknown Origin** | Upstream account compromise or typosquatted image name | Execution of unauthorized, malicious vendor code | Strict source image allowlist (`policy/data/config.json`) | Vendor build pipeline compromise prior to registry push |
| **2. Tag Mutation** | Upstream maintainer overwrites a mutable tag (e.g. `:latest`) | Silent deployment of altered code without re-evaluation | Instant digest resolution & SHA-256 digest pinning at intake | Registry availability or upstream digest deletion |
| **3. Vulnerability Decay** | Unpatched CVEs or active KEV exploits embedded in layers | Remote code execution or unauthorized privilege escalation | Trivy static scanning, CISA KEV blocking, EPSS threshold gating | Zero-day vulnerabilities with no public CVE record |
| **4. Embedded Secrets** | API tokens or private keys accidentally baked into image layers | Unauthorized access to internal infrastructure or third-party APIs | Layer-by-layer secret scanning via Trivy | Obfuscated or non-standard secret formats |
| **5. Licensing Liability** | Ingestion of prohibited copyleft software (e.g. AGPL-3.0) | Enforced open-sourcing of proprietary codebase or legal dispute | Component license classification & prohibited license gating | Incorrect license identification by scanner |
| **6. Known Malware** | Trojanized binaries or cryptominers embedded in vendor image | Resource hijacking, data exfiltration, or system destruction | ClamAV known-signature malware screening | Novel or custom obfuscated malware binaries |
| **7. Policy Bypass** | Bypassing CI checks to deploy unassessed container images | Ungoverned software execution in production runtime | `install.sh` / Cosign deployment verification of 4-digest pairing | Local root access on deployment node bypassing installer |

---

## 3. STRIDE Threat Analysis

- **Spoofing**: Mitigated by verifying OIDC workflow identity and upstream image allowlists.
- **Tampering**: Mitigated by SHA-256 digest pinning and Cosign keyless attestation signing.
- **Repudiation**: Mitigated by immutable signed promotion decision predicates and evidence manifests.
- **Information Disclosure**: Mitigated by secret scanning and static vulnerability analysis.
- **Denial of Service**: Mitigated by resource-bounded dynamic observation and KEV exploit blocking.
- **Elevation of Privilege**: Mitigated by eBPF syscall monitoring and runtime hardening checks.
