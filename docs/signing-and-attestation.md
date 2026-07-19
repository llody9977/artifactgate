# Signing and attestation

## Maintainer source history

The maintainer uses the same ED25519 SSH signing identity for ArtifactGate and
VulnSignal:

```text
SHA256:ZBn7MWG8WmRKUTE0rHqBZzwGWWb9f3nO/Rs9Pdhc0/k
```

The local repository is configured with `gpg.format=ssh`, signed commits and signed
tags. The private key remains on the maintainer's machine and must not be added to this
repository or copied into GitHub Actions.

## Published container evidence

Container releases use GitHub's OIDC-backed keyless artifact attestations. The workflow
receives a short-lived identity token and attaches separate provenance and SBOM
attestations to the immutable n8n and runner digests. Deployment verifies both subjects:

```bash
gh attestation verify oci://ghcr.io/llody9977/artifactgate/n8n-trusted@sha256:DIGEST -o llody9977
gh attestation verify oci://ghcr.io/llody9977/artifactgate/n8n-runners-trusted@sha256:DIGEST -o llody9977
```

The source-history key and workflow identity are intentionally distinct mechanisms.
Reusing the personal private key in CI would turn it into a long-lived repository secret
and weaken the trust model.
