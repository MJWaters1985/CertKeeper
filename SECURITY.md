# Security policy

CertKeeper holds SSH credentials for your hosts, private keys and a Cloudflare DNS token, so
security reports get priority.

## Reporting a vulnerability

Please report privately through GitHub: **Security › Report a vulnerability** on
[this repository](https://github.com/MJWaters1985/CertKeeper/security/advisories/new). Don't open a
public issue for anything that could put users at risk before it's fixed.

Include what's affected (Mac app, server or both, and the version), how to reproduce it, and what an
attacker could do with it. Reporters are credited in the release notes if they'd like to be.

## Supported versions

Fixes go into the latest release. Update to it before reporting, if you can.

## Scope

In scope: the Mac app, the server and its web interface, the container image, and the scripts
CertKeeper runs on hosts.

The administrator of a CertKeeper installation is trusted. They can already run commands on the
managed hosts (for example, with a custom install script), so things only they can do aren't
vulnerabilities.
