# CertKeeper server (Docker and TrueNAS)

The server edition runs the same engine as the Mac app in a container, with a web interface. It
issues Let's Encrypt certificates through Cloudflare DNS-01 and installs them on your hosts over
SSH, on a schedule, with no Mac needed.

## Run it

```yaml
# compose.yaml
services:
  certkeeper:
    image: ghcr.io/mjwaters1985/certkeeper:latest
    restart: unless-stopped
    user: "568:568"
    ports:
      - "8443:8443"
    volumes:
      - ./config:/config      # must be writable by uid 568
    stop_grace_period: 3m     # lets a running deployment finish on stop
```

```bash
mkdir -p config && sudo chown 568:568 config
docker compose up -d
docker compose logs certkeeper     # shows the one-time setup code
```

Open `https://<server>:8443`. The browser warns about the self-signed certificate until you give
CertKeeper a real one (see [HTTPS](#https)).

To build the image yourself (any architecture, from any host; no emulation needed):

```bash
docker build --platform linux/amd64 -t certkeeper .
```

## First start

1. The log prints a **one-time setup code**. Enter it in the web interface with the username and
   password you want. Without the code nobody else on your network can claim the server.
2. In **Settings**, add your Let's Encrypt email, accept the Subscriber Agreement and save a
   Cloudflare API token (Zone › DNS › Edit for your zones).
3. Copy **CertKeeper's SSH public key** (Settings › SSH key) into `~/.ssh/authorized_keys` for the
   user CertKeeper logs in as on each host, or give the host a password.
4. Add hosts, **Discover** what they serve, and adopt it.

Forgot the password? Stop the container, delete `config/users.json` and start it again: a new setup
code is printed. Nothing else is lost.

## Settings

| Variable | Default | |
|---|---|---|
| `CERTKEEPER_PORT` | `8443` | HTTPS port inside the container |
| `CERTKEEPER_HOST` | `0.0.0.0` | Address to listen on |
| `CERTKEEPER_CONFIG_DIR` | `/config` | All state; also `HOME` |
| `CERTKEEPER_TLS_CERT`, `CERTKEEPER_TLS_KEY` | | A certificate and key to serve, e.g. one TrueNAS manages. Set both or neither. |
| `CERTKEEPER_SECRET_KEY` | | Key for the secrets file (see [Secrets](#secrets)) |

## What's in /config

| File | |
|---|---|
| `inventory.json` | Hosts, certificates, deployments, settings and the activity log (no secrets) |
| `secrets.enc` | Cloudflare token, ACME account key, private keys, host passwords: AES-256-GCM |
| `secrets.key` | The key for `secrets.enc`, unless `CERTKEEPER_SECRET_KEY` is set |
| `users.json` | The administrator account (PBKDF2-SHA256 password hash) |
| `server.json` | Which managed certificate the web interface uses |
| `tls/` | The web interface's certificate: `fullchain.pem`/`privkey.pem` when managed, else `self-signed/` |
| `.ssh/` | CertKeeper's SSH key and `known_hosts` (new host keys are trusted on first use) |

Back up the whole folder. Settings › Configuration can also export everything to one file, with
the secrets encrypted by a password you choose.

## Secrets

`secrets.enc` is encrypted with a key that lives next to it in `secrets.key` by default. That
protects the secrets in exported configuration and in copies of the inventory, but not against
someone who can read the whole folder. To keep the key out of the folder, set
`CERTKEEPER_SECRET_KEY` (32 random bytes in base64, e.g. `openssl rand -base64 32`, or a long
passphrase) **before** the first start; then no `secrets.key` is written. If it's added, changed or
removed later, CertKeeper refuses to start rather than lose the secrets: set it back.

## HTTPS

The web interface always uses HTTPS. In order of preference:

1. **A certificate CertKeeper manages for itself.** Create a certificate for CertKeeper's own name
   (e.g. `certkeeper.example.com`), issue it, and pick it in Settings › Web interface HTTPS. It's
   renewed with the others and takes effect without a restart.
2. **A certificate from the platform.** Set `CERTKEEPER_TLS_CERT` and `CERTKEEPER_TLS_KEY` (TrueNAS
   can supply the one you choose in the install form). Renewed files are picked up within a minute.
3. **Self-signed**, made on first start.

## Its own IP address, DNS name and port 443 (TrueNAS)

To reach CertKeeper at `https://certkeeper.example.com` with no port number, give it a LAN address
of its own:

1. **Add an alias IP** to the NAS's network interface: Network › the interface › Aliases, e.g.
   `192.0.2.50/24`.
2. **Bind the app to it.** In the app's network settings, set the web port's bind mode to
   *Publish*, the host port to `443`, and add `192.0.2.50` under **Host IPs**. The container keeps
   listening on 8443; Docker publishes 443 on the alias.
3. **Free 443 on that address.** The TrueNAS web interface listens on every address by default,
   which blocks 443 on the alias. In System › General › GUI, set its IPv4 address to the NAS's main
   address only.
4. **Add a DNS record** pointing `certkeeper.example.com` at `192.0.2.50`, e.g. a host override in
   your LAN's resolver.
5. **Issue a certificate** for `certkeeper.example.com` in CertKeeper and pick it in Settings ›
   Web interface HTTPS.

Don't use macvlan for this: Docker blocks traffic between the host and a macvlan container, so
CertKeeper couldn't reach the NAS itself to rotate its certificate.

## Security notes

* CertKeeper holds SSH credentials for your hosts and a DNS-edit token: treat its web interface and
  `/config` like those credentials.
* It needs no extra Linux capabilities, no host networking and no `docker.sock`. It reaches the
  TrueNAS host it runs on over SSH, like any other host.
* Sessions are HTTP-only, secure, same-site cookies that end when the server restarts. Five wrong
  passwords from one address lock it out for 30 seconds, doubling up to 15 minutes.
* On stop, CertKeeper waits for running deployments to finish (up to about 3 minutes). A deployment
  that still gets cut off stays out of date and is redeployed by the first rotation pass after the
  restart.
