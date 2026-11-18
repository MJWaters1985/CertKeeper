# Changelog

All notable changes to CertKeeper. Versions follow [semantic versioning](https://semver.org/), and the
Mac app and the server share one version.

## 1.0.0 — 2026-11-18

The first public release, in two editions that share one engine:

- **CertKeeper for Mac** (macOS 15+): a native app that lives in the menu bar.
- **CertKeeper server** for Docker and TrueNAS, with a web interface: `ghcr.io/mjwaters1985/certkeeper`.

Both:

- Issue Let's Encrypt certificates (RSA or ECDSA, wildcards included) with DNS-01 validation through
  Cloudflare. Hosts never need an ACME client or the Cloudflare token.
- Find the certificates your hosts serve: run **Discover** on a host, then adopt what it finds.
- Install them over SSH on nginx (including separate instances, such as a KVM's web UI), Apache,
  Proxmox VE, TrueNAS (the web UI and catalog apps), UniFi OS, OPNsense, Pi-hole, apps that read
  certificate files (PEM or PKCS#12), devices with an HTTPS install API, or with your own script.
- Renew and redeploy only when needed. Each pass compares the certificate a service actually serves
  with the current one, and checks that the served chain is complete.
- Watch certificates that another system renews (monitor-only), with expiry warnings.
- Export certificates as PEM, PKCS#12, PKCS#7 or DER, and the whole configuration as one file with
  the secrets encrypted by a password.

The server adds:

- An HTTPS web interface with a single administrator account. On first start, a one-time setup
  code in the log protects the account setup.
- Its own HTTPS: a certificate CertKeeper manages for itself, one from TrueNAS, or a self-signed one.
  Renewals apply without a restart.
- Secrets in an AES-GCM encrypted file, and an SSH key of its own for hosts to trust.
- Safe stops: an update or restart waits for a running deployment to finish.
