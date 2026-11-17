# CertKeeper Server: plan

A Linux server edition of CertKeeper, shipped as a container image and submitted to the
TrueNAS community app catalog. The macOS app stays in this repository and shares the core.

## Decisions

- **One repository, shared Swift core.** CertKeeperCore builds on macOS and Linux; the Mac
  app and the server are two front ends. Every fix reaches both.
- **Public release.** The repository goes public only after the cleanup in step 1.

## Steps

### 1. Prepare the repository for publication

- Replace real hostnames and addresses with placeholders (`nas.example.com`,
  `192.0.2.0/24`) in sources, tests and docs.
- Rewrite commit authorship to the GitHub no-reply address and re-sign, or publish from a
  single squashed commit and keep the full history private. *(Open: which one.)*
- Choose a license. *(Open: GPL-3.0-or-later, MIT or Apache-2.0.)*

### 2. Linux server target

- Keep CertKeeperCore building on Linux. Platform-specific code sits behind
  `#if canImport(...)`:
  - Keychain → an encrypted secrets file under `/config`.
  - TLS probe and device API client (Network.framework) → SwiftNIO.
- A `CertKeeperServer` executable: a browser UI with every function the Mac app has, behind
  a login (the app holds SSH credentials and a Cloudflare token).
- Build and test on Linux in Docker. The Mac has no Linux toolchain.

### 3. Container

- Runs as uid/gid 568; all state under `/config`.
- Listening port from an environment variable, so the catalog form sets it. The container
  listens on an unprivileged port (it runs as uid 568); the host side can be 443, because
  Docker opens the published host port as root. Optional port 80 redirect to HTTPS.
- `/healthz` for the catalog's curl health check; keep curl in the image along with
  openssh-client and ca-certificates.
- **Safe stops.** Catalog updates restart the container whenever the user clicks Update.
  On SIGTERM, finish or roll back the deploy step in progress. Set a longer stop grace
  period, and run a recovery check at startup for anything left half-installed.
- **Secrets key.** Field masking in the install form is UI only. The encryption key for the
  secrets file comes from an environment variable when set (kept out of the volume), else a
  generated key file in `/config`. The README states what each option protects (a key in the
  volume protects backups and exports, not a compromised volume).
- No `docker.sock`, host networking or added capabilities. The server reaches its own
  TrueNAS host over SSH like any other host. Say so in the README and the catalog PR.

### 4. HTTPS for the server itself

The install form offers two modes:

- **TrueNAS certificate.** Pick one from the TrueNAS certificate store. TrueNAS writes the
  certificate files, and the server reloads them when they change.
- **Self-managed.** CertKeeper issues and renews a Let's Encrypt certificate for its own
  name through the same Cloudflare DNS-01 flow and reloads it without a restart. This works
  on any Docker host, not only TrueNAS.

### 5. Dedicated LAN address and DNS name (README setup guide)

Use the catalog's standard port options; no special app support is needed.

1. Add an alias IP to the NAS interface (Network → interface → Aliases), e.g. `192.0.2.50`.
2. In the app form, set the port's bind mode to *published* and add the alias under
   **Host IPs**.
3. To use port 443 on the alias, restrict the TrueNAS web interface to the NAS's main IP
   (System → General → GUI). By default it listens on every address, which blocks 443 on
   the alias. Otherwise pick another port.
4. Add a DNS record pointing the app's name (e.g. `certkeeper.example.com`) at the alias,
   such as a host override in the LAN resolver.
5. Choose self-managed HTTPS (step 4) for that name. The result is
   `https://certkeeper.example.com` on its own IP, with no port in the URL.

Not macvlan: the catalog form doesn't offer it, and Docker blocks traffic between the host
and a macvlan container, which would stop CertKeeper from managing the NAS's own certificate.

### 6. Build and release

- The NAS is x86-64 and the development Mac is ARM. Build the amd64 image with Swift's
  static Linux SDK (cross-compiled, no emulation) or on GitHub's x86 runners; run Linux
  tests natively in an ARM container.
- Pushing a `vX.Y.Z` tag runs the macOS and Linux tests and publishes
  `ghcr.io/mjwaters1985/certkeeper` (`X.Y.Z`, `X.Y`, `X`, `latest`). The workflow
  checks the version and a CHANGELOG section first. Optionally attach a Mac app zip.

### 7. Test privately, then submit

- Run it as a private YAML app on a separate dataset; keep a dev instance apart from the
  real one.
- Open an app-request issue on `truenas/apps` first (the app-request label is the go-ahead).
- Catalog entry in `ix-dev/community/`: ix_volume storage by default, port from the form,
  curl health check, private fields for secrets, README, several test value files.
- PR from the app-addition template: tick the LLM box, list only what was actually tested,
  link the icon and screenshots from this repository.
- Expect maintainer edits (defaults, notes). Their metadata tools are x86-only, so apply the
  diff CI prints. After the merge, Renovate picks up new tags; no version-bump PRs.
