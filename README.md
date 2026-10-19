# CertKeeper

A native macOS app (SwiftUI, macOS 15+) that issues Let's Encrypt certificates using Cloudflare
DNS-01 validation and rotates them onto remote hosts over SSH. It keeps an inventory, so it only
renews and redeploys when needed.

## How it works

```
Mac (CertKeeper)                                      Hosts
 ├─ ACME client ──► Let's Encrypt                      nginx · Apache · Proxmox VE
 ├─ Cloudflare API ─► _acme-challenge TXT records      TrueNAS · UniFi OS · OPNsense
 └─ /usr/bin/ssh ──────────────────────────────────►   install script per target
```

* **Issuance happens on the Mac.** Hosts never see the Cloudflare token and don't need an ACME client installed.
* **Secrets stay in the login Keychain**: the Cloudflare token, the ACME account key, and each certificate's private key.
  The inventory (hosts, certificates, deployments, log) is `~/Library/Application Support/CertKeeper/inventory.json`.
* **SSH uses the system OpenSSH client**, so `~/.ssh/config`, ssh-agent, the 1Password/Secretive agents and hardware
  keys all work. Connections are multiplexed. New host keys are trusted on first use.
* **Passwords (optional, per host)** are stored in the Keychain. Keys are always tried first.
  * *SSH login:* ssh runs the CertKeeper binary as its `SSH_ASKPASS` helper, and it reads the password from the
    Keychain. The password never appears in arguments or environment variables, and only "password" prompts are
    answered (never key passphrases).
  * *sudo:* CertKeeper first checks `sudo -n`. Only if that fails does it run `sudo -k -S` with the password on the
    first stdin line, so a password can never reach the shell as a command.
* **Rotation pass** (runs every N hours, or from ⇧⌘R / the menu bar):
  1. A certificate is (re)issued when it has never been issued, is within its renewal window (default 30 days),
     has expired, or its domain list has changed.
  2. Every deployment is checked: the app reads the certificate the host is actually using, plus the live TLS
     endpoint if one is configured, and compares SHA-256 fingerprints.
  3. Any deployment that isn't serving the current certificate gets redeployed.

## Targets

| Target | What the default script does |
|---|---|
| nginx | Backs up and replaces the cert/key files, runs `nginx -t` (rolling back on failure), then reloads |
| Apache | Same as nginx, using `apachectl -t` and a graceful reload. Full chain goes in `SSLCertificateFile` unless a chain path is set |
| Proxmox VE | `pvenode cert set … --force 1 --restart 1` (custom pveproxy cert; the cluster CA is untouched) |
| TrueNAS | `midclt` import → web UI and/or catalog apps (see below) → deletes old copies nothing references → restarts the UI |
| Pi-hole (v6) | Writes key + full chain into FTL's TLS file (`webserver.tls.cert`, default `/etc/pihole/tls.pem`), optionally sets `webserver.domain` to the certificate's name, then restarts `pihole-FTL` (or the Docker container) |
| App (cert files) | For apps that read their own certificate files (qBittorrent, Jellyfin, Compose stacks…). Writes the files (optionally `chown`ed, e.g. `568:568`), then redeploys the TrueNAS app or restarts the container / Compose project, or runs your reload command |
| UniFi OS | Replaces `unifi-core.crt/.key` (auto-detected) → restarts `unifi-core` |
| OPNsense | PHP: imports into System › Trust (reusing the previous CertKeeper entry) → sets the web GUI cert → `configctl webgui restart` |
| Device (HTTPS API) | For devices without SSH (hosts with connection *Device API*). `PUT /api/tls/certificate` with the full chain and key, authenticated by the device's API token; the device checks the pair and switches its HTTPS server over |
| Custom | Your own script |

Every script can be viewed and overridden per deployment (*Customize install script*). The scripts get
`$CERT $CHAIN $FULLCHAIN $KEY $TARGET_CERT $TARGET_KEY $TARGET_CHAIN $CERT_NAME $DOMAINS` and the helpers
`ck_install` (backs up, keeps the 3 newest backups) and `ck_rollback`.

### TrueNAS apps

TrueNAS can't replace an imported certificate in place, so every renewal creates a new certificate entry.

* **Catalog apps** (apps with a *Certificate* setting, TrueNAS 24.10+). One TrueNAS deployment can cover the web UI
  and any number of apps. On each deploy:
  1. Apps still using an older CertKeeper copy of the certificate are repointed automatically, along with any apps
     listed in *Catalog apps*. They're updated through `app.update`, which redeploys them.
  2. Old copies are deleted only if neither the UI nor any app still references them. A failed app update leaves that
     app's certificate in place and marks the deploy as failed.
  3. Discovery lists each app's certificate. Adopting an app adds it to the existing TrueNAS deployment for that certificate.
* **Apps that handle HTTPS themselves** (no TrueNAS certificate setting) use *App (cert files)*. Discovery finds
  **Jellyfin** (`network.xml` → a PKCS#12 `.pfx`) and **qBittorrent** (`qBittorrent.conf` → PEM cert and key) by
  looking in the app's config volumes. It maps the paths inside the container to real paths on the NAS, and picks up
  the file format, restart target and HTTPS port, so adopting needs no manual setup. Reading those volumes usually
  needs *Use sudo* on the host. For other apps or Compose stacks, enter the paths yourself.

**Discovery** (Host › Discover) scans for nginx (`nginx -T`; skipped on TrueNAS), Apache vhosts, qBittorrent
(native `qbittorrent-nox` — by process, `--profile` or home folder, restarted through its systemd unit — or Docker), Pi-hole v6
(native, or Docker containers running a `pihole` image, mapped to the host volume), the Proxmox pveproxy cert, the TrueNAS UI
cert, UniFi `unifi-core.crt`, and the OPNsense web GUI cert. *Adopt* turns a discovered certificate into a managed one,
reusing an existing managed certificate when the names match.

### Device API hosts

Some devices, such as an ESP32-S3 board running firmware with this API, have no shell. They install certificates
through a small HTTPS API instead:

* `GET /api/tls` returns the certificate being served: `source` (`installed` or `self-signed`), subject, issuer,
  `not_after`, `sha256` (of the leaf DER), `dns_names` and `chain_length`.
* `PUT /api/tls/certificate` takes JSON `{"certificate": "<PEM chain, leaf first>", "private_key": "<PEM>"}`.
* Both need `Authorization: Bearer <token>`. CertKeeper keeps the token in the Keychain as the host's password.

Until a publicly trusted certificate is installed, the device serves a self-signed one. CertKeeper sends the token
and private keys only to a certificate macOS trusts for the host's name, or to the one whose SHA-256 is pinned on
the host. The host editor's **Fetch** button reads the fingerprint; pin it only if it matches the one the device
shows. Requests use Network.framework rather than URLSession, because App Transport Security makes URLSession
refuse untrusted certificates even when the app has chosen to trust them. Self-signed certificates also have to
meet Apple's TLS rules (serverAuth EKU, valid for 825 days or less), or macOS rejects them outright.

## Setup

```sh
./build-app.sh            # → build/CertKeeper.app
open build/CertKeeper.app
```

**Signing (do this once).** Keychain remembers "Always Allow" by Apple team ID only for apps signed with an
Apple-issued certificate. Ad-hoc and self-signed builds are remembered by their exact build hash, so after every
rebuild Keychain asks again, once per stored secret. To stop that, create a free **Apple Development** certificate:

1. Xcode › Settings › Accounts › **+** › Apple ID (a free account is enough).
2. Select your team › **Manage Certificates…** › **+** › **Apple Development**.

`build-app.sh` picks it up automatically (or pass any identity: `./build-app.sh "Developer ID Application: …"`).
The first launch after switching asks once per item — choose **Always Allow** — and rebuilds keep access after that.

1. **Settings › Cloudflare**: add a scoped API token with *Zone › Zone › Read* and *Zone › DNS › Edit*, then click **Verify**.
2. **Settings › Let's Encrypt**: enter an email and accept the Subscriber Agreement. Leave it on **Staging** until a full
   issue → deploy → verify cycle works, then switch to Production.
3. Add hosts. Use key-based SSH or a stored password, as root or as a user with sudo (enable *Use sudo*).
4. Run **Discover** on each host and adopt what it finds, or create certificates and add deployments manually.

## Exporting certificates

**Export…** on a certificate writes it with its full chain in a choice of formats. Private keys are written
readable only by you, and you're asked before existing files are replaced. The last format used is remembered.

| Format | Files | Typical use |
|---|---|---|
| PEM, separate files | `NAME.cert.pem`, `.chain.pem`, `.fullchain.pem`, `.privkey.pem` | nginx, Apache, most Linux tools |
| PEM, single file | `NAME.pem` (private key, then full chain) | HAProxy, Pi-hole, lighttpd |
| PKCS#12 | `NAME.p12` (full chain + key, password protected; AES-256, or 3DES for older systems) | Windows/IIS, macOS Keychain, Java, Jellyfin |
| PKCS#7 + key | `NAME.p7b` (full chain) + `NAME.key` (PEM) | Windows, Java |
| DER + key | `NAME.cer`, `NAME.chain-N.cer`, `NAME.key.der` (PKCS#8) | Windows, appliances, Android |

PKCS#12 and PKCS#7 are produced with macOS's `/usr/bin/openssl`, in a private temporary folder.

## Exporting and importing the configuration

**File › Export Configuration…** (⇧⌘E) saves hosts, certificates, deployments, settings and ACME account links to
a JSON file; the activity log isn't included. Secrets (Cloudflare token, ACME account key, certificate private keys,
host passwords, .pfx passwords) are only included if you tick the box. They're then encrypted with a password you
choose: PBKDF2-SHA256 with 600,000 iterations, then AES-256-GCM. Without them the file contains no passwords or keys.

**File › Import Configuration…** (⇧⌘I) shows what the file contains and asks before replacing the current
configuration. The current inventory is first saved to `inventory.before-import-<time>.json` next to it, and the
activity log is kept. Secrets in the file go to the Keychain. After import, the log lists certificates without a
private key (reissue them before deploying) and hosts without a password.

## App icon

`Support/Icons/CertKeeper.icon` is a layered Icon Composer icon: a certificate behind a gold seal and ribbons, on a
teal gradient. Its layers are flat, full-bleed SVGs with no baked-in shadows or gloss; macOS 26+ applies the
rounded-square mask, Liquid Glass, depth and shadow itself. `build-app.sh` compiles it with `actool` into
`Assets.car`, plus a flattened `CertKeeper.icns` for older macOS. To change it, edit `certificate_layers()` in
`Support/Icons/make_icons.py` and run `python3 make_icons.py --icon`, or open the `.icon` in Icon Composer
(Xcode › Open Developer Tool). The other concepts and their previews are kept in the same folder.

## Tests

```sh
swift test                                           # unit tests, plus running the real deploy and discovery scripts against stubs
CK_ACME_STAGING=1 swift test --filter ACMEStaging    # live check against Let's Encrypt staging (no DNS changes)
```

## Caveats: verify these on your versions before trusting production

* **UniFi OS Server** (self-hosted, podman-based) has no documented certificate path. The script searches
  `/data /mnt /var/lib /opt /srv` for `unifi-core.crt` and tries `systemctl`, `unifi-os`, then `podman exec uosserver`.
  Set `UNIFI_DIR` in the script if detection gets it wrong. Firmware updates on UniFi consoles can overwrite the certificate;
  the next rotation pass will detect the drift and redeploy.
* **OPNsense**: the script edits the legacy `$config` array and calls `write_config()`. This matches how the Trust store has
  traditionally been stored, but newer releases are moving Trust to MVC models, so test on your version. A backup of
  `/conf/config.xml` is taken first, and OPNsense also keeps its own config history. Root's login shell on OPNsense is the
  console menu; non-interactive `ssh … sh -s` normally passes through it, but a dedicated admin user with sudo is more robust.
* **TrueNAS**: uses `midclt` (`certificate.create` with `CERTIFICATE_CREATE_IMPORTED`, plus `app.query` with
  `retrieve_config` and `app.update`). This was written for SCALE / Community Edition 24.10+, not CORE, and is tested
  against a simulated middleware rather than a real system. App updates send back the app's full config with only the
  `certificate_id` fields changed.
* The app has to be running for scheduled rotation. It stays in the menu bar, and *Open at login* is in Settings › Schedule.
