# Installing and running CertKeeper on TrueNAS

CertKeeper is a TrueNAS app with an HTTPS web interface. It issues Let's Encrypt certificates through
Cloudflare DNS-01 and installs them on your hosts over SSH, on a schedule.

* [Install on TrueNAS](#install-on-truenas)
* [First start](#first-start)
* [Hosts and SSH](#hosts-and-ssh)
* [HTTPS for the web interface](#https-for-the-web-interface)
* [Its own address, name and port 443 on TrueNAS](#its-own-address-name-and-port-443-on-truenas)
* [Settings](#settings) · [What's in /config](#whats-in-config) · [Secrets](#secrets)
* [Backups, updates and moving](#backups-updates-and-moving)
* [Troubleshooting](#troubleshooting) · [Security](#security)

## Install on TrueNAS

On TrueNAS Community Edition 24.10 or later, install CertKeeper as a custom app:

1. **Create a dataset for its data**, for example `tank/certkeeper`, with the **Apps** preset. Edit its
   permissions so the owner user and group are **apps** (568).
2. Open **Apps › Discover Apps**, choose **⋮ › Install via YAML**, name the app `certkeeper`, and paste:

   ```yaml
   services:
     certkeeper:
       image: ghcr.io/mjwaters1985/certkeeper:1.0.0
       restart: unless-stopped
       user: "568:568"
       ports:
         - "30600:8443"                  # https://<nas>:30600
       volumes:
         - /mnt/tank/certkeeper:/config  # the dataset from step 1
       stop_grace_period: 3m             # lets a running deployment finish on stop
   ```

3. **Save**. When the app is running, open its **Logs**: they show the one-time setup code for the
   [first start](#first-start).

To reach CertKeeper at `https://certkeeper.example.com` without a port number, see
[its own address, name and port 443](#its-own-address-name-and-port-443-on-truenas).

## First start

1. The log shows a **one-time setup code**. Open the web interface and enter it with the username and
   password you want (at least 10 characters). Without the code, nobody else on your network can claim the
   server. Missed it? Restart CertKeeper: a new code is printed until the account exists.
2. In **Settings › Let's Encrypt**, enter your email, accept the Subscriber Agreement and save. Start with
   **staging** until a full issue → deploy → check cycle works, then turn it off for trusted certificates.
3. In **Settings › Cloudflare**, save an API token and **Verify** it. See
   [the Cloudflare API token](cloudflare-token.md) for the permissions it needs.
4. **Add hosts** (see below), **Discover** what they serve, and **Adopt** it, or create certificates and add
   deployments yourself.

## Hosts and SSH

* **Logging in.** On first start CertKeeper creates an SSH key. Copy its public key from
  **Settings › SSH key** into `~/.ssh/authorized_keys` of the user CertKeeper logs in as on each host. Or
  store a password on the host and tick *Log in with the password when keys don't work*. CertKeeper always
  tries the key first.
* **Privileges.** Log in as root, or as a user with sudo and tick *Use sudo*. With sudo, CertKeeper first
  tries passwordless `sudo -n`, then the stored password.
* **Host keys.** A host's SSH key is trusted the first time CertKeeper connects and checked after that.
  If a host is rebuilt and its key changes, connecting fails with *REMOTE HOST IDENTIFICATION HAS CHANGED*.
  Once you've confirmed the change is expected, remove the old key in the app's **Shell** (Apps › CertKeeper
  › Workloads › Shell):

  ```sh
  ssh-keygen -R host.example.com -f /config/.ssh/known_hosts
  ```

* **SSH settings.** CertKeeper's home folder is `/config`, so `/config/.ssh/config` works like
  `~/.ssh/config` for jump hosts, ports or user names.
* **Devices without SSH** use the *Device API* connection; see
  [Device API hosts](../README.md#device-api-hosts).

## HTTPS for the web interface

The web interface only uses HTTPS. Its certificate is, in order of preference:

1. **One CertKeeper manages for itself.** Create a certificate for CertKeeper's own name (for example
   `certkeeper.example.com`), issue it, and pick it in **Settings › Web interface HTTPS**. It's renewed
   with the others and switched in without a restart. The certificate's page lists it as deployed to
   *This CertKeeper · Web interface*.
2. **One from the platform.** Set `CERTKEEPER_TLS_CERT` and `CERTKEEPER_TLS_KEY` to PEM files in the
   container. Renewed files are picked up within a minute.
3. **Self-signed**, made on first start.

If the chosen certificate's files can't be loaded, CertKeeper still starts, on its self-signed certificate,
logs which file is the problem, and switches over once the files are fixed.

## Its own address, name and port 443 on TrueNAS

To reach CertKeeper at `https://certkeeper.example.com`, give it a LAN address of its own:

1. **Add an alias IP** to the NAS's network interface: **Network › the interface › Aliases**, for example
   `192.0.2.50/24`. TrueNAS asks you to confirm the network change within 60 seconds.
2. **Free port 443 on that address.** The TrueNAS web interface listens on every address by default. In
   **System › General Settings › GUI**, set its IPv4 address to the NAS's main address only. It stays
   reachable there.
3. **Bind the app to the alias.** In the app's YAML, change the port line to `"192.0.2.50:443:8443"` and
   save.
4. **Add a DNS record** pointing `certkeeper.example.com` at `192.0.2.50`, for example a host override in
   your LAN's DNS resolver.
5. **Issue a certificate** for `certkeeper.example.com` in CertKeeper and pick it in
   **Settings › Web interface HTTPS**.

Don't use macvlan for this: Docker blocks traffic between the host and a macvlan container, so CertKeeper
couldn't reach the NAS itself to manage its certificates.

## Settings

| Variable | Default | |
|---|---|---|
| `CERTKEEPER_PORT` | `8443` | HTTPS port inside the app's container |
| `CERTKEEPER_HOST` | `0.0.0.0` | Address to listen on inside the app's container |
| `CERTKEEPER_CONFIG_DIR` | `/config` | All state; also `HOME` |
| `CERTKEEPER_TLS_CERT`, `CERTKEEPER_TLS_KEY` | | A certificate and key (PEM files mounted into the app) for the web interface. Set both or neither |
| `CERTKEEPER_SECRET_KEY` | | The key for the secrets file (see [Secrets](#secrets)) |
| `CERTKEEPER_SCHEDULE` | `on` | `off` stops automatic rotation passes (for demos and tests) |

Everything else (Let's Encrypt account, renewal window, schedule, log retention) is in the web
interface's **Settings**.

CertKeeper runs as uid 568 (TrueNAS's `apps` user) by default, but any uid works, as long as it can write
`/config`.

## What's in /config

| File | |
|---|---|
| `inventory.json` | Hosts, certificates, deployments, settings and the activity log (no secrets) |
| `secrets.enc` | The Cloudflare token, ACME account key, private keys and passwords, encrypted (AES-256-GCM) |
| `secrets.key` | The key for `secrets.enc`, unless `CERTKEEPER_SECRET_KEY` is set |
| `users.json` | The administrator account (a PBKDF2-SHA256 password hash) |
| `server.json` | Which certificate the web interface uses |
| `tls/` | The web interface's certificate: `fullchain.pem` and `privkey.pem` when managed, `self-signed/` otherwise |
| `.ssh/` | CertKeeper's SSH key, `known_hosts` and an optional `config` |
| `inventory.before-import-*.json` | Copies saved before each configuration import |

The activity log is also written to the app's **Logs**.

## Secrets

`secrets.enc` is encrypted with a key that lives next to it, in `secrets.key`. That protects the secrets
in configuration exports and in copies of the inventory, but not against someone who can read the whole
folder.

To keep the key out of the folder, set `CERTKEEPER_SECRET_KEY` before the first start: 32 random bytes in
base64 (`openssl rand -base64 32`), or a long passphrase. No `secrets.key` is written then. If the variable
is later added, changed or removed, CertKeeper refuses to start rather than lose the secrets; set it back.

## Backups, updates and moving

* **Backups.** Snapshot or replicate the app's dataset, which holds everything in `/config`.
  **Settings › Configuration › Export** with a password also saves everything, secrets included, in one
  file.
* **Updates.** Edit the app's YAML (Apps › CertKeeper › Edit) and change the image tag. Releases are listed
  on the
  [releases page](https://github.com/MJWaters1985/CertKeeper/releases). On stop, CertKeeper waits up to
  about three minutes for a running deployment to finish. A deployment that still gets cut off stays out of
  date and is redeployed by the first rotation pass after the restart.
* **Moving to another NAS.** Export the configuration with a password, install CertKeeper on the new NAS,
  and import the file in **Settings › Configuration**. Then add the new installation's SSH key to your
  hosts, or rely on the imported host passwords. Stop the old installation, so the two don't both renew
  the same certificates.

## Troubleshooting

| Problem | What to do |
|---|---|
| The setup code is gone from the log | Restart CertKeeper; a new code is printed until an account exists |
| Forgot the password | Stop CertKeeper, delete `users.json` in `/config` and start it: a new setup code is printed. Nothing else is lost |
| *Too many failed logins* | Wait: after five wrong passwords from one address, it's locked out for 30 seconds, doubling up to 15 minutes. Restarting clears it |
| The browser says the certificate isn't trusted | Expected with the self-signed certificate; see [HTTPS](#https-for-the-web-interface). With a managed certificate, use the name on it, not the IP address |
| The log says the web interface's certificate couldn't be loaded | CertKeeper fell back to its self-signed certificate. Fix the files it names, and it switches over within a minute |
| *No Cloudflare zone accessible to this token contains …* | The token can't see the zone of that name; see [the token's permissions](cloudflare-token.md) |
| *Timed out waiting for TXT record … to propagate* | Public DNS didn't show the challenge record in time. Try again, or raise *DNS propagation timeout* in Settings |
| *REMOTE HOST IDENTIFICATION HAS CHANGED* | The host's SSH key changed; see [host keys](#hosts-and-ssh) |
| *Permission denied* over SSH | Add CertKeeper's public key to the host, or store the host's password and allow password login |
| A deployment says *Needs attention* | The service's configuration no longer reads the files CertKeeper writes, for example after a firmware update reset it. Check the deployment's paths, or discover the host again |
| Let's Encrypt rate limits | Use staging while testing. Production allows only a few certificates for the same names each week |

The activity log (and the app's **Logs**) has the details of each step.

## Security

* CertKeeper holds SSH credentials for your hosts and a DNS-edit token. Treat its web interface and
  `/config` like those credentials.
* It needs no extra Linux capabilities, no host networking and no `docker.sock`. It reaches the TrueNAS host
  it runs on over SSH, like any other host.
* There's one administrator account. Sessions are secure, HTTP-only, same-site cookies that end when
  CertKeeper restarts. Changes need a header a cross-site page can't send.
* Report vulnerabilities privately; see [SECURITY.md](../SECURITY.md).
