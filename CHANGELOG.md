# Changelog

All notable changes to CertKeeper. Versions follow [semantic versioning](https://semver.org/).

## 1.0.0 — 2026-11-18

The first public release: a TrueNAS app with a web interface (`ghcr.io/mjwaters1985/certkeeper`).

- Issues Let's Encrypt certificates (ECDSA or RSA, wildcards included) with DNS-01 validation through
  Cloudflare. Hosts never need an ACME client or the Cloudflare token.
- Finds the certificates your hosts serve: run **Discover** on a host, then adopt what it finds.
- Installs them over SSH on nginx (including separate instances, such as a KVM's web UI), Apache,
  Proxmox VE, TrueNAS (the web UI and catalog apps), UniFi OS, OPNsense, Pi-hole, apps that read
  certificate files (PEM or PKCS#12), devices with an HTTPS install API, or with your own script.
- Renews and redeploys only when needed. Each rotation pass compares the certificate a service actually
  serves with the current one, and checks that the served chain is complete.
- Watches certificates that another system renews (monitor only), with expiry warnings.
- Exports certificates as PEM, PKCS#12, PKCS#7 or DER, and the whole configuration as one file with the
  secrets encrypted by a password.
- One administrator account, protected on first start by a one-time setup code in the log.
- HTTPS for its own web interface: a certificate CertKeeper manages for itself, one you provide, or a
  self-signed one. Renewals apply without a restart.
- Secrets in an AES-GCM encrypted file, and an SSH key of its own for hosts to trust.
- Safe stops: an update or restart waits for a running deployment to finish.
