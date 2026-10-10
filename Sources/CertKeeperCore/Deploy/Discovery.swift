import Foundation

/// Finds TLS certificates in use on a host. Output protocol (one block per endpoint):
///
///     @@ENDPOINT kind|label|certPath|keyPath|chainPath
///     -----BEGIN CERTIFICATE----- … (leaf only)
///     @@END
public enum Discovery {
    public struct Report: Sendable {
        public var os: String
        public var endpoints: [DiscoveredEndpoint]
        public var warnings: [String]
    }

    public static let script = #"""
    set +e
    PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin"
    echo "@@OS $(uname -s) $( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -r)"

    first_cert() { sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$1" 2>/dev/null | awk '/BEGIN CERT/{n++} n==1'; }
    emit() {  # kind label cert key chain [options] [note]
      printf '@@ENDPOINT %s|%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "${6:-}" "${7:-}"
      if [ -r "$3" ]; then first_cert "$3"; else echo "@@WARN cannot read $3"; fi
      echo "@@END"
    }

    # ---- nginx ----
    # Every running nginx master is inspected with its own -p/-c (e.g. a GL.iNet/PiKVM web UI runs a
    # second instance); the default config is used when none is running.
    # (skipped on TrueNAS: its nginx serves the web UI and is managed by the middleware)
    if command -v nginx >/dev/null 2>&1 && ! command -v midclt >/dev/null 2>&1; then
      ngx_instances=$(for f in "${CK_PROC:-/proc}"/[0-9]*/cmdline; do
          [ -r "$f" ] || continue
          tr '\0' ' ' < "$f" | awk '/^nginx: master process/ {
            p = ""; c = ""; for (i = 1; i <= NF; i++) { if ($i == "-p") p = $(i + 1); if ($i == "-c") c = $(i + 1) }
            print p "|" c }'
        done | sort -u)
      [ -n "$ngx_instances" ] || ngx_instances="|"
      for ngx in $ngx_instances; do
        ngx_p=${ngx%%|*}; ngx_c=${ngx#*|}
        ngx_args=""
        [ -n "$ngx_p" ] && ngx_args="-p $ngx_p"
        [ -n "$ngx_c" ] && ngx_args="$ngx_args -c $ngx_c"
        ngx_opts=""
        [ -n "$ngx_c" ] && ngx_opts="nginx_conf=$ngx_c${ngx_p:+;nginx_prefix=$ngx_p}"
        ngx_dir=$(dirname "${ngx_c:-/etc/nginx/nginx.conf}")
        nginx $ngx_args -T 2>/dev/null | awk '
          { sub(/#.*/, "") }
          $1 == "server_name" { sn = $0; sub(/^[ \t]*server_name[ \t]+/, "", sn); sub(/;.*/, "", sn) }
          $1 == "ssl_certificate"     { c = $2; gsub(/[;"\047]/, "", c) }
          $1 == "ssl_certificate_key" { k = $2; gsub(/[;"\047]/, "", k) }
          c != "" && k != "" { print c "|" k "|" sn; c = ""; k = "" }
        ' | sort -u | while IFS='|' read -r c k sn; do
          case "$c" in *'$'*) echo "@@WARN skipping variable path $c"; continue;; esac
          # relative paths are resolved against the config file's directory
          case "$c" in /*) ;; *) c="$ngx_dir/$c" ;; esac
          case "$k" in /*) ;; *) k="$ngx_dir/$k" ;; esac
          emit nginx "$sn${ngx_c:+ [$ngx_c]}" "$c" "$k" "" "$ngx_opts"
        done
      done
    fi

    # ---- Apache ----
    for dir in /etc/apache2/sites-enabled /etc/apache2/conf-enabled /etc/apache2/mods-enabled \
               /etc/httpd/conf /etc/httpd/conf.d /usr/local/etc/apache24; do
      [ -d "$dir" ] || continue
      grep -rliE 'SSLCertificateFile' "$dir" 2>/dev/null
    done | sort -u | while read -r f; do
      awk '
        { line = $0; sub(/#.*/, "", line); n = split(line, a, /[ \t]+/); key = ""; val = ""
          for (i = 1; i <= n; i++) if (a[i] != "") { key = tolower(a[i]); val = a[i + 1]; break }
          gsub(/"/, "", val) }
        key == "servername"              { sn = val }
        key == "sslcertificatefile"      { c = val }
        key == "sslcertificatekeyfile"   { k = val }
        key == "sslcertificatechainfile" { ch = val }
        key == "</virtualhost>"          { if (c != "") print c "|" k "|" ch "|" sn; c = ""; k = ""; ch = ""; sn = "" }
        END                              { if (c != "") print c "|" k "|" ch "|" sn }
      ' "$f"
    done | sort -u | while IFS='|' read -r c k ch sn; do
      emit apache "$sn" "$c" "${k:-$c}" "$ch"
    done

    # ---- Pi-hole v6 (pihole-FTL web server; native or Docker) ----
    ph_strip() { tr -d '"' | head -n 1; }
    ph_tls_port() {  # webserver.port, e.g. "80o,443os,[::]:443os" -> first TLS port
      tr ',' '\n' | awk 'match($0, /[0-9]+[a-z]*$/) { t = substr($0, RSTART, RLENGTH); n = t; sub(/[a-z]+$/, "", n)
                         if (substr(t, length(n) + 1) ~ /s/) { print n; exit } }'
    }
    if command -v pihole-FTL >/dev/null 2>&1; then
      ph_cert=$(pihole-FTL --config webserver.tls.cert 2>/dev/null | ph_strip)
      ph_domain=$(pihole-FTL --config webserver.domain 2>/dev/null | ph_strip)
      ph_port=$(pihole-FTL --config webserver.port 2>/dev/null | ph_tls_port)
      [ -n "$ph_cert" ] || ph_cert=/etc/pihole/tls.pem
      ph_note=""
      [ -n "$ph_port" ] || ph_note="HTTPS is not enabled in Pi-hole's webserver.port"
      if [ -f "$ph_cert" ]; then
        emit pihole "Web UI (${ph_domain:-pi.hole})" "$ph_cert" "$ph_cert" "" \
          "pihole_set_domain=true${ph_port:+;verify_port=$ph_port}" "$ph_note"
      else
        echo "@@WARN Pi-hole: TLS file $ph_cert not found (CertKeeper supports Pi-hole v6)"
      fi
    fi
    if command -v docker >/dev/null 2>&1; then
      for c in $(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | awk '$2 ~ /pihole/ { print $1 }'); do
        ph_cert=$(docker exec "$c" pihole-FTL --config webserver.tls.cert 2>/dev/null | ph_strip)
        ph_domain=$(docker exec "$c" pihole-FTL --config webserver.domain 2>/dev/null | ph_strip)
        ph_cport=$(docker exec "$c" pihole-FTL --config webserver.port 2>/dev/null | ph_tls_port)
        [ -n "$ph_cert" ] || ph_cert=/etc/pihole/tls.pem
        # container path -> host path through the longest matching mount
        ph_host=$(docker inspect -f '{{range .Mounts}}{{println .Destination .Source}}{{end}}' "$c" 2>/dev/null | awk -v p="$ph_cert" '
          NF >= 2 { d = $1; sub(/\/$/, "", d)
                    if ((p == d || index(p, d "/") == 1) && length(d) > best) { best = length(d); out = $2 substr(p, length(d) + 1) } }
          END { print out }')
        ph_port=""
        [ -n "$ph_cport" ] && ph_port=$(docker port "$c" "$ph_cport/tcp" 2>/dev/null | head -n 1 | sed 's/.*://')
        if [ -n "$ph_host" ]; then
          emit pihole "Container $c (${ph_domain:-pi.hole})" "$ph_host" "$ph_host" "" \
            "pihole_set_domain=true;restart_target=$c${ph_port:+;verify_port=$ph_port}"
        else
          echo "@@WARN Pi-hole container $c: $ph_cert is not on a mounted volume"
        fi
      done
    fi

    # ---- qBittorrent: native qbittorrent-nox or Docker (TrueNAS apps are handled above) ----
    qb_val() { K="$2" awk -F= '$1 == ENVIRON["K"] { sub(/^[^=]*=/, ""); print; exit }' "$1" 2>/dev/null; }
    qb_owner() { stat -c '%u:%g' "$1" 2>/dev/null || stat -f '%u:%g' "$1" 2>/dev/null; }
    qb_map() {  # container path, "dest src" mount lines -> host path (longest mount wins)
      printf '%s\n' "$2" | awk -v p="$1" 'NF >= 2 { d = $1; sub(/\/$/, "", d)
        if ((p == d || index(p, d "/") == 1) && length(d) > best) { best = length(d); out = $2 substr(p, length(d) + 1) } }
        END { print out }'
    }
    qb_emit() {  # conf restart_target label [mounts container]
      qb_c=$(qb_val "$1" 'WebUI\HTTPS\CertificatePath'); qb_k=$(qb_val "$1" 'WebUI\HTTPS\KeyPath')
      qb_en=$(qb_val "$1" 'WebUI\HTTPS\Enabled'); qb_port=$(qb_val "$1" 'WebUI\Port'); qb_port=${qb_port:-8080}
      if [ -z "$qb_c$qb_k" ]; then echo "@@WARN qBittorrent $3: Web UI HTTPS has no certificate files configured in $1"; return; fi
      if [ -n "${4:-}" ]; then
        qb_c=$(qb_map "$qb_c" "$4"); qb_k=$(qb_map "$qb_k" "$4")
        if [ -z "$qb_c" ] || [ -z "$qb_k" ]; then echo "@@WARN qBittorrent $3: certificate files are not on a mounted volume"; return; fi
        qb_hp=$(docker port "$5" "$qb_port/tcp" 2>/dev/null | head -n 1 | sed 's/.*://'); qb_port=${qb_hp:-$qb_port}
      fi
      qb_note=""
      [ "$qb_en" = true ] || qb_note="HTTPS is turned off in qBittorrent's Web UI settings"
      [ -n "$2" ] || qb_note="${qb_note:+$qb_note; }no service found to restart — set one before deploying"
      qb_own=$(qb_owner "$qb_c")
      emit containerApp "qBittorrent Web UI ($3)" "$qb_c" "$qb_k" "" \
        "cert_format=pem;restart_target=$2;verify_port=$qb_port${qb_own:+;file_owner=$qb_own}" "$qb_note"
    }
    qb_unit_for_user() {  # first qBittorrent systemd unit that exists for this user
      for u in "qbittorrent-nox@$1.service" qbittorrent-nox.service qbittorrent.service; do
        if systemctl cat "$u" >/dev/null 2>&1; then echo "systemd:$u"; return; fi
      done
    }
    if ! command -v midclt >/dev/null 2>&1; then
      qb_seen=""
      # running qbittorrent-nox processes (skipping ones inside containers, found below)
      for qb_line in $(ps -eo pid=,user=,args= 2>/dev/null | awk '$3 ~ /(^|\/)qbittorrent(-nox)?$/ {
                         prof = ""; for (i = 4; i <= NF; i++) { if ($i ~ /^--profile=/) { prof = substr($i, 11) } else if ($i == "--profile") { prof = $(i + 1) } }
                         print $1 "|" $2 "|" prof }'); do
        qb_pid=${qb_line%%|*}; qb_rest=${qb_line#*|}; qb_user=${qb_rest%%|*}; qb_prof=${qb_rest#*|}
        qb_unit=$(ps -o unit= -p "$qb_pid" 2>/dev/null | tr -d ' ')
        case "$qb_unit" in docker-*|*containerd*|libpod-*) continue ;; esac
        if [ -n "$qb_prof" ]; then qb_conf="$qb_prof/qBittorrent/config/qBittorrent.conf"
        else qb_conf="$(getent passwd "$qb_user" | cut -d: -f6)/.config/qBittorrent/qBittorrent.conf"; fi
        [ -f "$qb_conf" ] || continue
        case " $qb_seen " in *" $qb_conf "*) continue ;; esac
        qb_seen="$qb_seen $qb_conf"
        case "$qb_unit" in *.service) qb_target="systemd:$qb_unit" ;; *) qb_target=$(qb_unit_for_user "$qb_user") ;; esac
        qb_emit "$qb_conf" "$qb_target" "$qb_user"
      done
      # not running: look in regular users' homes
      for qb_line in $(getent passwd 2>/dev/null | awk -F: '($3 >= 1000 && $3 < 60000) || $3 == 0 || $1 ~ /qbittorrent/ { print $1 "|" $6 }'); do
        qb_user=${qb_line%%|*}; qb_conf="${qb_line#*|}/.config/qBittorrent/qBittorrent.conf"
        [ -f "$qb_conf" ] || continue
        case " $qb_seen " in *" $qb_conf "*) continue ;; esac
        qb_seen="$qb_seen $qb_conf"
        qb_emit "$qb_conf" "$(qb_unit_for_user "$qb_user")" "$qb_user"
      done
      # Docker containers running a qBittorrent image
      if command -v docker >/dev/null 2>&1; then
        for qb_ctr in $(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | awk 'tolower($2) ~ /qbittorrent/ { print $1 }'); do
          qb_mounts=$(docker inspect -f '{{range .Mounts}}{{println .Destination .Source}}{{end}}' "$qb_ctr" 2>/dev/null)
          qb_conf=""
          for qb_src in $(printf '%s\n' "$qb_mounts" | awk 'tolower($1) ~ /config/ { print $2 }'); do
            qb_conf=$(find "$qb_src" -maxdepth 4 -type f -name qBittorrent.conf 2>/dev/null | head -n 1)
            [ -n "$qb_conf" ] && break
          done
          if [ -z "$qb_conf" ]; then echo "@@WARN qBittorrent container $qb_ctr: no qBittorrent.conf in its config volumes"; continue; fi
          qb_emit "$qb_conf" "$qb_ctr" "container $qb_ctr" "$qb_mounts" "$qb_ctr"
        done
      fi
    fi

    # ---- Proxmox VE ----
    if [ -d /etc/pve/local ]; then
      if [ -f /etc/pve/local/pveproxy-ssl.pem ]; then
        emit proxmox "pveproxy (custom)" /etc/pve/local/pveproxy-ssl.pem /etc/pve/local/pveproxy-ssl.key "" "verify_port=8006"
      else
        emit proxmox "pveproxy (self-signed)" /etc/pve/local/pve-ssl.pem /etc/pve/local/pve-ssl.key "" "verify_port=8006"
      fi
    fi

    # ---- TrueNAS (web UI, catalog apps, and apps that terminate TLS themselves; 24.10+) ----
    if command -v midclt >/dev/null 2>&1; then
      python3 - <<'PY'
    import json, os, re, subprocess

    def mid(*args):
        cmd = ["midclt", "call"] + [a if isinstance(a, str) else json.dumps(a) for a in args]
        return json.loads(subprocess.check_output(cmd, stderr=subprocess.PIPE))

    def endpoint(kind, label, cert, key="", chain="", pem="", options=None, note=None):
        opts = ";".join("%s=%s" % (k, v) for k, v in (options or {}).items())
        print("@@ENDPOINT %s|%s|%s|%s|%s|%s|%s" % (kind, label, cert, key, chain, opts, note or ""))
        if pem:
            print(pem)
        print("@@END")

    def first_cert(text):
        m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text or "", re.S)
        return m.group(0) if m else ""

    certs = {}
    def truenas_cert(cid):
        if cid not in certs:
            certs[cid] = mid("certificate.query", [["id", "=", cid]], {"get": True})
        return certs[cid]

    def cert_ids(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "certificate_id" and isinstance(v, int):
                    yield v
                else:
                    yield from cert_ids(v)
        elif isinstance(node, list):
            for v in node:
                yield from cert_ids(v)

    def read(path):
        try:
            with open(path, errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def pem_from_pfx(path, password):
        for extra in ([], ["-legacy"]):
            p = subprocess.run(["openssl", "pkcs12", "-in", path, "-nokeys", "-passin", "pass:" + password] + extra,
                               capture_output=True, text=True)
            if p.returncode == 0:
                return first_cert(p.stdout)
        return ""

    def mounts_of(app):
        """[(container_path, host_path)] for an app, longest container path first."""
        found = []
        wl = app.get("active_workloads") or {}
        for c in wl.get("container_details") or []:
            for m in c.get("volume_mounts") or []:
                found.append((m.get("destination"), m.get("source")))
        for m in wl.get("volumes") or []:
            found.append((m.get("destination"), m.get("source")))
        if not found:
            # Fallback when the middleware doesn't report mounts: ask Docker (needs root).
            try:
                ids = subprocess.check_output(["docker", "ps", "-q", "--filter",
                                               "label=com.docker.compose.project=ix-" + app["name"]],
                                              stderr=subprocess.DEVNULL, text=True).split()
                for info in json.loads(subprocess.check_output(["docker", "inspect"] + ids, text=True)) if ids else []:
                    for m in info.get("Mounts") or []:
                        found.append((m.get("Destination"), m.get("Source")))
            except Exception:
                pass
        found = [(d.rstrip("/") or "/", s) for d, s in found if d and s]
        return sorted(set(found), key=lambda m: -len(m[0]))

    def host_path(container_path, mounts):
        for dest, src in mounts:
            if container_path == dest or container_path.startswith(dest + "/"):
                return src + container_path[len(dest):]
        return None

    def host_port(app, container_port):
        for p in (app.get("active_workloads") or {}).get("used_ports") or []:
            if str(p.get("container_port")) == str(container_port):
                for hp in p.get("host_ports") or []:
                    if hp.get("host_port"):
                        return str(hp["host_port"])
        return str(container_port)

    def find_files(mounts, names, max_depth=4):
        """Looks for the given file names in config-like mounts (not media libraries)."""
        hits = []
        for dest, src in mounts:
            if "config" not in dest.lower() or not os.path.isdir(src):
                continue
            base = src.rstrip("/").count("/")
            for root, dirs, files in os.walk(src):
                if root.count("/") - base >= max_depth:
                    dirs[:] = []
                hits += [os.path.join(root, f) for f in files if f in names]
        return hits

    def owner(path):
        try:
            st = os.stat(path)
            return "%d:%d" % (st.st_uid, st.st_gid)
        except OSError:
            return ""

    def xml_value(text, tag):
        m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), text, re.S)
        return m.group(1).strip() if m else ""

    def ini_value(text, key):
        m = re.search(r"^" + re.escape(key) + r"=(.*)$", text, re.M)
        return m.group(1).strip() if m else ""

    def jellyfin(app, mounts):
        """Jellyfin/Emby: network.xml points at a PKCS#12 file."""
        for conf in find_files(mounts, {"network.xml"}):
            text = read(conf) or ""
            if "<CertificatePath" not in text:
                continue
            cpath = xml_value(text, "CertificatePath")
            enabled = xml_value(text, "EnableHttps").lower() == "true"
            port = xml_value(text, "InternalHttpsPort") or xml_value(text, "HttpsPortNumber") or "8920"
            label = "App: %s (Jellyfin HTTPS)" % app["name"]
            if not cpath:
                print("@@WARN %s: HTTPS has no certificate configured in %s" % (app["name"], conf))
                continue
            hpath = host_path(cpath, mounts)
            if not hpath:
                print("@@WARN %s: certificate %s is not on a mounted volume" % (app["name"], cpath))
                continue
            password = xml_value(text, "CertificatePassword")
            opts = {"cert_format": "pkcs12", "restart_target": app["name"], "verify_port": host_port(app, port)}
            if os.path.exists(hpath):
                opts["file_owner"] = owner(hpath)
            if password:
                opts["pfx_password"] = password
            note = None if enabled else "HTTPS is turned off in Jellyfin's networking settings"
            endpoint("containerApp", label, hpath, pem=pem_from_pfx(hpath, password) if os.path.exists(hpath) else "",
                     options=opts, note=note)
            return True
        return False

    def qbittorrent(app, mounts):
        """qBittorrent: qBittorrent.conf names PEM certificate and key files for the Web UI."""
        for conf in find_files(mounts, {"qBittorrent.conf"}):
            text = read(conf) or ""
            cpath = ini_value(text, r"WebUI\HTTPS\CertificatePath")
            kpath = ini_value(text, r"WebUI\HTTPS\KeyPath")
            if not cpath and not kpath:
                print("@@WARN %s: Web UI HTTPS is not configured in %s" % (app["name"], conf))
                continue
            hc, hk = host_path(cpath, mounts), host_path(kpath, mounts)
            if not hc or not hk:
                print("@@WARN %s: certificate/key (%s, %s) not on a mounted volume" % (app["name"], cpath, kpath))
                continue
            enabled = ini_value(text, r"WebUI\HTTPS\Enabled").lower() == "true"
            port = ini_value(text, r"WebUI\Port") or "8080"
            opts = {"cert_format": "pem", "restart_target": app["name"], "verify_port": host_port(app, port)}
            if os.path.exists(hc):
                opts["file_owner"] = owner(hc)
            endpoint("containerApp", "App: %s (qBittorrent Web UI)" % app["name"], hc, hk,
                     pem=first_cert(read(hc)), options=opts,
                     note=None if enabled else "HTTPS is turned off in qBittorrent's Web UI settings")
            return True
        return False

    try:
        ui = mid("system.general.config").get("ui_certificate")
        cid = ui.get("id") if isinstance(ui, dict) else ui
        c = truenas_cert(cid)
        endpoint("truenas", "Web UI (%s)" % c.get("name", ""), "ui", pem=first_cert(c.get("certificate")))
    except Exception as e:
        print("@@WARN TrueNAS UI certificate query failed: %s" % e)
    try:
        apps = mid("app.query", [], {"extra": {"retrieve_config": True}})
    except Exception as e:
        apps = []
        print("@@WARN TrueNAS app query failed (apps need 24.10+): %s" % e)
    for app in apps:
        found = False
        for cid in sorted(set(cert_ids(app.get("config") or {}))):
            try:
                c = truenas_cert(cid)
                endpoint("truenas", "App: %s (%s)" % (app["name"], c.get("name", "")), "app:" + app["name"],
                         pem=first_cert(c.get("certificate")))
                found = True
            except Exception as e:
                print("@@WARN certificate %s for app %s: %s" % (cid, app["name"], e))
        mounts = mounts_of(app)
        if not found and mounts:
            found = jellyfin(app, mounts) or qbittorrent(app, mounts)
        if not found:
            why = "no TrueNAS certificate selected"
            why += "; no mounts reported" if not mounts else "; no Jellyfin/qBittorrent HTTPS config in its config volumes"
            if mounts and not os.access(mounts[0][1], os.R_OK):
                why += " (config not readable — enable sudo for this host)"
            print("@@WARN app %s: %s" % (app["name"], why))
    PY
    fi

    # ---- UniFi OS: consoles (/data/unifi-core/config) and UniFi OS Server, which runs UniFi OS in a
    # podman container (rootless, as user uosserver) with the same files in its data volume and
    # serves the UI on 11443. ${CK_ROOT} is an alternate filesystem root, used by the tests.
    for d in "${CK_ROOT:-}"/data/unifi-core/config "${CK_ROOT:-}"/mnt/data/unifi-core/config \
               "${CK_ROOT:-}"/home/*/.local/share/containers/storage/volumes/*/_data/unifi-core/config \
               "${CK_ROOT:-}"/var/lib/containers/storage/volumes/*/_data/unifi-core/config \
               $(find "${CK_ROOT:-}"/data "${CK_ROOT:-}"/mnt "${CK_ROOT:-}"/var/lib "${CK_ROOT:-}"/opt "${CK_ROOT:-}"/srv \
                   -maxdepth 6 -type f -name unifi-core.crt 2>/dev/null | head -n 5 | xargs -n1 dirname 2>/dev/null); do
      [ -f "$d/unifi-core.crt" ] && echo "$d"
    done | sort -u | while read -r d; do
      case "$d" in
        */containers/storage/volumes/*) emit unifiOS "UniFi OS Server (unifi-core)" "$d/unifi-core.crt" "$d/unifi-core.key" "" "unifi_dir=$d;verify_port=11443" ;;
        *) emit unifiOS "UniFi OS console (unifi-core)" "$d/unifi-core.crt" "$d/unifi-core.key" "" "unifi_dir=$d" ;;
      esac
    done

    # ---- OPNsense ----
    if [ -x /usr/local/bin/php ] && [ -f /usr/local/etc/inc/config.inc ] && command -v configctl >/dev/null 2>&1; then
      /usr/local/bin/php <<'PHP'
    <?php
    require_once('config.inc');
    global $config;
    $ref = $config['system']['webgui']['ssl-certref'] ?? '';
    $certs = $config['cert'] ?? [];
    if (isset($certs['refid'])) { $certs = [$certs]; }
    foreach ($certs as $c) {
        if (($c['refid'] ?? '') !== $ref) continue;
        $pem = base64_decode($c['crt'] ?? '');
        $end = '-----END CERTIFICATE-----';
        $descr = str_replace('|', '/', $c['descr'] ?? '');
        $port = $config['system']['webgui']['port'] ?? '';
        if ($port === '') { $port = '443'; }
        $note = stripos($descr, 'ACME') !== false
            ? "Issued by OPNsense's ACME Client plugin. Once CertKeeper has deployed, turn off this certificate's automatic renewal in Services > ACME Client > Certificates."
            : '';
        echo "@@ENDPOINT opnsense|Web GUI ({$descr})||||verify_port={$port}|{$note}\n";
        echo explode($end, $pem)[0] . $end . "\n@@END\n";
    }
    PHP
    fi
    exit 0
    """#

    public static func parse(_ output: String) -> Report {
        var os = ""
        var endpoints: [DiscoveredEndpoint] = []
        var warnings: [String] = []
        var current: DiscoveredEndpoint?
        var pem = ""

        for raw in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(raw)
            if line.hasPrefix("@@OS ") {
                os = String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("@@WARN ") {
                warnings.append(String(line.dropFirst(7)))
            } else if line.hasPrefix("@@ENDPOINT ") {
                let fields = line.dropFirst(11).split(separator: "|", omittingEmptySubsequences: false).map(String.init)
                guard fields.count >= 5, let kind = DeploymentKind(rawValue: fields[0]) else { continue }
                current = DiscoveredEndpoint(
                    kind: kind,
                    label: fields[1].trimmingCharacters(in: .whitespaces),
                    certPath: fields[2], keyPath: fields[3], chainPath: fields[4], summary: nil
                )
                if fields.count > 5, !fields[5].isEmpty {
                    current?.options = Dictionary(fields[5].split(separator: ";").compactMap { pair in
                        let kv = pair.split(separator: "=", maxSplits: 1).map(String.init)
                        return kv.count == 2 ? (kv[0], kv[1]) : nil
                    }, uniquingKeysWith: { $1 })
                }
                if fields.count > 6, !fields[6].isEmpty { current?.note = fields[6] }
                pem = ""
            } else if line == "@@END" {
                if var ep = current {
                    ep.summary = try? CertCrypto.summarize(pem: pem)
                    if !endpoints.contains(where: { $0.id == ep.id }) { endpoints.append(ep) }
                }
                current = nil
            } else if current != nil {
                pem += line + "\n"
            }
        }
        return Report(os: os, endpoints: endpoints, warnings: warnings)
    }

    /// Prints the first certificate in a PEM file, or in a PKCS#12 file when `pkcs12` is set.
    public static func probeScript(path: String, pkcs12: Bool, password: String = "") -> String {
        let extract = "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | awk '/BEGIN CERT/{n++} n==1'"
        guard pkcs12 else { return "\(extract) < \(shellQuote(path))" }
        return """
        CK_PFX_PASS=\(shellQuote(password)); export CK_PFX_PASS
        { openssl pkcs12 -in \(shellQuote(path)) -nokeys -passin env:CK_PFX_PASS 2>/dev/null \
          || openssl pkcs12 -legacy -in \(shellQuote(path)) -nokeys -passin env:CK_PFX_PASS; } | \(extract)
        """
    }

    public static func run(on host: ManagedHost, ssh: SSHRunner = SSHRunner()) async throws -> Report {
        let result = try await ssh.run(script, on: host, timeout: 120)
        if result.status == 255 {
            throw SSHRunner.SSHError(message: "SSH to \(host.name) failed: \(result.stderr)", result: result)
        }
        var report = parse(result.stdout)
        if report.os.isEmpty, !result.stderr.isEmpty {
            report.warnings.append(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return report
    }

    /// The discovered endpoint that corresponds to a deployment (same kind; same cert path when path-based).
    public static func match(_ deployment: Deployment, in endpoints: [DiscoveredEndpoint]) -> DiscoveredEndpoint? {
        relevantEndpoints(for: deployment, in: endpoints).first
    }

    /// Every endpoint a deployment is responsible for. A TrueNAS deployment can cover the web UI and
    /// any number of catalog apps; a named app that wasn't found yields a placeholder with no summary.
    public static func relevantEndpoints(for deployment: Deployment, in endpoints: [DiscoveredEndpoint]) -> [DiscoveredEndpoint] {
        let candidates = endpoints.filter { $0.kind == deployment.kind }
        switch deployment.kind {
        case _ where deployment.kind.usesFilePaths:
            return candidates.filter { $0.certPath == deployment.certPath }
        case .truenas:
            var result: [DiscoveredEndpoint] = []
            if deployment.flag(.truenasUI) {
                result += candidates.filter { truenasApp($0) == nil }
            }
            for app in deployment.truenasApps {
                result.append(candidates.first { truenasApp($0) == app }
                    ?? DiscoveredEndpoint(kind: .truenas, label: "App: \(app)", certPath: "app:\(app)", keyPath: "", chainPath: "", summary: nil))
            }
            return result
        default:
            return Array(candidates.prefix(1))
        }
    }

    /// For nginx/Apache: whether that server's current config still reads the deployment's certificate
    /// file, and which files it reads instead. nil when discovery found nothing for that server instance.
    public static func configStillUses(_ d: Deployment, in endpoints: [DiscoveredEndpoint]) -> (inUse: Bool, current: [String])? {
        guard d.kind == .nginx || d.kind == .apache else { return nil }
        let conf = d.option(.nginxConf)
        let sameServer = endpoints.filter {
            $0.kind == d.kind && (d.kind == .apache || ($0.options?[DeploymentOption.nginxConf.rawValue] ?? "") == conf)
        }
        guard !sameServer.isEmpty else { return nil }
        let paths = sameServer.map(\.certPath).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
        return (paths.contains(d.certPath), paths)
    }

    /// The catalog app name for a TrueNAS app endpoint, nil for the web UI.
    public static func truenasApp(_ endpoint: DiscoveredEndpoint) -> String? {
        guard endpoint.kind == .truenas, endpoint.certPath.hasPrefix("app:") else { return nil }
        return String(endpoint.certPath.dropFirst(4))
    }
}
