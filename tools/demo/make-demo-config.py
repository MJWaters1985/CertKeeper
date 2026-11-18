#!/usr/bin/env python3
"""Writes a CertKeeper server configuration full of example.com demo data, for screenshots.

    python3 tools/demo/make-demo-config.py /tmp/certkeeper-demo

Everything is made up: the hosts don't exist, and the certificates are self-signed stand-ins with
Let's Encrypt-style details in the inventory. Run the server on it with CERTKEEPER_SCHEDULE=off so it
never tries to reach the hosts. Sign in as demo / demo-password-1.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc).replace(microsecond=0)
ISSUER = "CN=YE1,O=Let's Encrypt,C=US"


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(**kw):
    return iso(NOW - timedelta(**kw))


def ident():
    return str(uuid.uuid4()).upper()


def certificate(names, days_left):
    """A self-signed stand-in (only its PEM and fingerprint are used) and its inventory summary."""
    san = ",".join(f"DNS:{n}" for n in names)
    pem = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", "/dev/null", "-subj", f"/CN={names[0]}", "-addext", f"subjectAltName={san}", "-days", "90"],
        capture_output=True, text=True, check=True).stdout
    der = subprocess.run(["openssl", "x509", "-outform", "DER"], input=pem.encode(), capture_output=True, check=True).stdout
    not_after = NOW + timedelta(days=days_left, hours=6)
    summary = {"subject": f"CN={names[0]}", "issuer": ISSUER, "serial": os.urandom(9).hex(),
               "notBefore": iso(not_after - timedelta(days=90)), "notAfter": iso(not_after),
               "dnsNames": names, "sha256": hashlib.sha256(der).hexdigest()}
    return pem, summary


def main(out):
    os.makedirs(out, exist_ok=True)
    hosts, certs, deps, log = [], [], [], []

    def host(name, user, notes, sudo=False, seen_hours=2, connection="ssh", port=22):
        h = {"id": ident(), "name": name, "address": name, "port": port, "username": user, "identityFile": "",
             "useSudo": sudo, "passwordLogin": True, "notes": notes, "lastSeen": ago(hours=seen_hours),
             "lastDiscovery": [], "connection": connection, "apiPinnedSHA256": ""}
        hosts.append(h)
        return h

    def cert(names, days_left, monitored=False, issued_days_ago=None, error=None):
        pem, summary = certificate(names, days_left)
        c = {"id": ident(), "name": names[0], "domains": names, "keyAlgorithm": "ECDSA P-256", "autoRenew": True,
             "current": summary, "leafPEM": pem, "chainPEM": ""}
        if monitored:
            c["external"] = True
        else:
            c["lastIssued"] = ago(days=issued_days_ago if issued_days_ago is not None else 90 - days_left)
        if error:
            c["lastError"] = error
        certs.append(c)
        return c

    def deploy(c, h, kind, current=True, checked_hours=1, **fields):
        d = {"id": ident(), "certificateID": c["id"], "hostID": h["id"], "kind": kind, "certPath": "", "keyPath": "",
             "chainPath": "", "verifyEndpoint": "", "enabled": True, "options": {}, "forceRedeploy": False,
             "lastChecked": ago(hours=checked_hours)}
        d.update(fields)
        sha = c["current"]["sha256"]
        d["deployedSHA256"] = sha if current else os.urandom(32).hex()
        d["deployedNotAfter"] = c["current"]["notAfter"] if current else ago(days=-12)
        if current:
            d["lastDeployed"] = c.get("lastIssued") or ago(days=10)
            d["servedChainComplete"] = True
        deps.append(d)
        return d

    nas = host("nas.example.com", "truenas_admin", "Linux TrueNAS 25.10.1", sudo=True)
    pve = host("pve.example.com", "root", "Linux Debian GNU/Linux 13 (trixie)")
    web = host("web1.example.com", "deploy", "Linux Ubuntu 24.04.3 LTS", sudo=True)
    fw = host("fw.example.com", "root", "FreeBSD 14.3-RELEASE-p4 (OPNsense)")
    dns = host("pihole.example.com", "root", "Linux Debian GNU/Linux 12 (bookworm)", seen_hours=5)
    kvm = host("kvm.example.com", "root", "Linux Buildroot (GL.iNet KVM)")
    uos = host("unifi.example.com", "admin", "Linux Ubuntu 24.04.3 LTS (UniFi OS Server)", sudo=True)
    lab = host("lab-pi.example.com", "pi", "Linux Debian GNU/Linux 13 (trixie)", sudo=True, seen_hours=26)

    c_nas = cert(["nas.example.com"], 61)
    c_pve = cert(["pve.example.com"], 61)
    c_www = cert(["example.com", "www.example.com"], 74)
    c_lab = cert(["*.lab.example.com"], 22)
    c_fw = cert(["fw.example.com"], 66)
    c_dns = cert(["pihole.example.com"], 58)
    c_kvm = cert(["kvm.example.com"], 61)
    c_uos = cert(["unifi.example.com"], 47, monitored=True)
    c_ck = cert(["certkeeper.example.com"], 83)

    deploy(c_nas, nas, "truenas", certPath="ui", options={"truenas_ui": "true"})
    deploy(c_nas, nas, "containerApp", certPath="/mnt/tank/apps/jellyfin/config/nas.example.com.p12",
           options={"cert_format": "pkcs12", "restart_target": "jellyfin", "file_owner": "568:568"})
    deploy(c_nas, nas, "containerApp", certPath="/mnt/tank/apps/qbittorrent/config/cert.pem",
           keyPath="/mnt/tank/apps/qbittorrent/config/key.pem", options={"cert_format": "pem", "restart_target": "qbittorrent"})
    deploy(c_pve, pve, "proxmox", verifyEndpoint="pve.example.com:8006")
    deploy(c_www, web, "nginx", certPath="/etc/nginx/ssl/example.com.pem", keyPath="/etc/nginx/ssl/example.com.key",
           verifyEndpoint="www.example.com:443")
    deploy(c_lab, web, "nginx", current=False, checked_hours=1, certPath="/etc/nginx/ssl/lab.pem",
           keyPath="/etc/nginx/ssl/lab.key")
    deploy(c_fw, fw, "opnsense")
    deploy(c_dns, dns, "pihole", certPath="/etc/pihole/tls.pem", options={"pihole_set_domain": "true"}, checked_hours=5)
    deploy(c_kvm, kvm, "nginx", certPath="/etc/kvmd/user/ssl/server.crt", keyPath="/etc/kvmd/user/ssl/server.key",
           options={"nginx_conf": "/etc/kvmd/nginx-kvmd.conf", "nginx_prefix": "/etc/kvmd/nginx"})
    deploy(c_uos, uos, "unifiOS", options={"unifi_dir": "/home/uosserver/.local/share/containers/storage/volumes/uosserver_data/_data/unifi-core/config"})
    deploy(c_lab, lab, "containerApp", current=False, checked_hours=26, certPath="/etc/lab-app/tls/fullchain.pem",
           keyPath="/etc/lab-app/tls/privkey.pem", options={"restart_target": "systemd:lab-app.service"},
           lastError="SSH to lab-pi.example.com failed: ssh: connect to host lab-pi.example.com port 22: No route to host")

    # The NAS's last discovery: what's managed, plus one app that isn't yet.
    def endpoint(kind, label, path, c, note=None, options=None):
        return {"kind": kind, "label": label, "certPath": path, "keyPath": "", "chainPath": "",
                "summary": c["current"], "options": options, "note": note}
    _, nextcloud = certificate(["cloud.example.com"], 12)
    nextcloud["issuer"] = "CN=TrueNAS self-signed"
    nas["lastDiscovery"] = [
        endpoint("truenas", "Web UI (certkeeper_nas_example_com)", "ui", c_nas, options={"truenas_ui": "true"}),
        endpoint("containerApp", "App: jellyfin (Jellyfin HTTPS)", "/mnt/tank/apps/jellyfin/config/nas.example.com.p12", c_nas,
                 options={"cert_format": "pkcs12", "restart_target": "jellyfin"}),
        endpoint("containerApp", "App: qbittorrent (qBittorrent Web UI)", "/mnt/tank/apps/qbittorrent/config/cert.pem", c_nas,
                 options={"cert_format": "pem", "restart_target": "qbittorrent"}),
        {"kind": "truenas", "label": "App: nextcloud", "certPath": "app:nextcloud", "keyPath": "", "chainPath": "",
         "summary": nextcloud, "options": {"truenas_apps": "nextcloud", "truenas_ui": "false"},
         "note": "Uses TrueNAS's self-signed certificate."},
    ]

    def entry(level, message, hours, detail=None):
        e = {"id": ident(), "date": ago(hours=hours), "level": level, "message": message}
        if detail:
            e["detail"] = detail
        log.append(e)

    entry("success", "Rotation pass finished", 0.9, "1 deployment out of date, 1 unreachable")
    entry("error", "Check failed on lab-pi.example.com", 0.95,
          "SSH to lab-pi.example.com failed: ssh: connect to host lab-pi.example.com port 22: No route to host")
    entry("warning", "*.lab.example.com is served out of date on web1.example.com", 0.97)
    entry("info", "Rotation pass started", 1.0)
    entry("success", "Verified pve.example.com is live on pve.example.com", 30)
    entry("success", "Deployed pve.example.com → pve.example.com (Proxmox VE)", 30.1, "pvenode cert set: restarted pveproxy")
    entry("success", "Issued pve.example.com", 30.2, f"Expires {c_pve['current']['notAfter'][:10]}")
    entry("info", "Domain validation passed", 30.25)
    entry("info", "Published 1 DNS challenge record(s); waiting for propagation", 30.3)
    entry("info", "Requesting certificate for pve.example.com", 30.4, "Let's Encrypt production")
    entry("success", "Discovered 4 certificate(s) on nas.example.com", 52, "Linux TrueNAS 25.10.1")

    inventory = {
        "hosts": hosts, "certificates": certs, "deployments": deps, "log": log, "acmeAccounts": {},
        "settings": {"acmeEmail": "admin@example.com", "useStaging": False, "renewDaysBeforeExpiry": 30,
                     "checkIntervalHours": 12, "autoDeploy": True, "dnsPropagationTimeout": 300,
                     "acceptedTermsOfService": True, "logRetentionDays": 90},
    }
    with open(os.path.join(out, "inventory.json"), "w") as f:
        json.dump(inventory, f, indent=1)

    # The demo account, hashed the way the server expects (PBKDF2-SHA256, 600,000 rounds).
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", b"demo-password-1", salt, 600_000)
    with open(os.path.join(out, "users.json"), "w") as f:
        json.dump({"username": "demo", "passwordHash":
                   f"pbkdf2-sha256$600000${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"}, f)
    print(f"Demo configuration in {out}: {len(hosts)} hosts, {len(certs)} certificates, {len(deps)} deployments")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
