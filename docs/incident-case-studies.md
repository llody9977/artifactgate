# Supply Chain Incident Case Studies & Control Derivations

This document analyzes 5 major real-world supply chain incidents, detailing what failed, the design requirements derived, ArtifactGate's mitigations, and remaining limitations.

---

## Case Study 1: `tj-actions/changed-files` (CI/CD Action Compromise)

- **Incident Overview**: A widely used third-party GitHub Action repository was compromised, and mutable git release tags (e.g. `:v40`) were moved to point to malicious commit SHAs designed to exfiltrate pipeline secrets.
- **What Failed**: Mutable release tags allowed silent code replacement in downstream CI/CD pipelines without maintainer awareness or re-review.
- **Design Requirement Derived**: CI/CD workflows and intake pipelines must pin third-party actions and container images strictly to immutable cryptographic commit SHAs and OCI digests.
- **ArtifactGate Control**: All GitHub Actions in ArtifactGate workflows are SHA256/commit-SHA pinned (`actions/checkout@9c091bb2...`), and container image intake resolves mutable tags to immutable SHA-256 digests.
- **Remaining Limitation**: Upstream registries could theoretically delete digests or become unavailable.

---

## Case Study 2: XZ Utils Backdoor (Targeted Maintainer & Build Compromise)

- **Incident Overview**: A malicious actor spent years establishing trust in the open-source XZ Utils repository before introducing a sophisticated build-time backdoor into `liblzma` tarballs, targeted at SSH authentication daemon binaries.
- **What Failed**: Code review and maintainer reputation failed to prevent intentional malicious logic introduced during tarball build steps.
- **Design Requirement Derived**: Static vulnerability scanners cannot detect custom logic bombs. Systems require runtime dynamic observation and strict assurance boundaries.
- **ArtifactGate Control**: Tracee kernel-level eBPF syscall auditing captures unexpected dynamic behavior (e.g. unauthorized binary execution or file access) during quarantine test execution.
- **Remaining Limitation**: Complex logic bombs that trigger only under specific multi-stage runtime conditions may bypass bounded dynamic observation.

---

## Case Study 3: SolarWinds Orion (Vendor Build Pipeline Compromise)

- **Incident Overview**: Attackers compromised SolarWinds' internal build environment, inserting a backdoor (`SUNBURST`) into legitimate software updates signed by the vendor's valid code-signing certificate.
- **What Failed**: Valid vendor signatures and publisher identities proved only that the software came from the vendor, not that the software was free from internal compromise.
- **Design Requirement Derived**: Upstream signatures cannot prove code safety. Downstream promotion must evaluate security evidence independently and generate separate downstream promotion attestations.
- **ArtifactGate Control**: ArtifactGate evaluates security evidence independently of vendor signatures, attesting downstream promotion decisions (`promotiondecision` predicate) based on actual assessment results.
- **Remaining Limitation**: ArtifactGate does not attempt to reconstruct missing upstream SLSA build provenance for third-party vendor images.

---

## Case Study 4: Equifax Apache Struts (Vulnerability Management SLA Breakdown)

- **Incident Overview**: Apache Struts vulnerability CVE-2017-5638 was publicly disclosed with an available patch, but internal remediation processes failed, leaving an internet-facing application unpatched for months until exploited.
- **What Failed**: Finding a vulnerability was insufficient; asset management, accountable risk ownership, remediation SLAs, and exception expiration were missing.
- **Design Requirement Derived**: Risk exceptions must have accountable owners, documented compensating controls, and strict expiration dates that enforce automatic re-review.
- **ArtifactGate Control**: OpenVEX exception waivers (`waiver.json`) enforce mandatory risk owners, expiration dates (`expires_on`), and active waiver-to-CVE coverage validation in `validate_vex.py`.
- **Remaining Limitation**: Manual review by security risk owners relies on human diligence during waiver renewal.

---

## Case Study 5: Log4Shell (Post-Release Security Decay)

- **Incident Overview**: A critical zero-day vulnerability (CVE-2021-44228 in Apache Log4j) affected millions of deployed enterprise applications, requiring immediate identification of deployed instances across global infrastructure.
- **What Failed**: Organizations could not identify which deployed container images contained Log4j because software composition inventories were not retained or linked to running workloads.
- **Design Requirement Derived**: Software composition (SBOM) must be bound to exact deployed digests, and deployed artifacts must undergo continuous scheduled re-scanning.
- **ArtifactGate Control**: Signed SPDX 2.3 SBOMs are bound to promoted digests, and `rescan.yml` executes weekly scheduled vulnerability re-scans against all promoted images.
- **Remaining Limitation**: Automatic post-release revocation and container teardown are not fully automated; re-scan failures currently create GitHub issues for manual intervention.
