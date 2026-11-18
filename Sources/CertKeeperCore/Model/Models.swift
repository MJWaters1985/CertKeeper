import Foundation

// MARK: - Hosts

/// How CertKeeper reaches a host.
public enum HostConnection: String, Codable, CaseIterable, Identifiable, Sendable {
    /// Shell over SSH: discovery and install scripts.
    case ssh
    /// A device that installs certificates through its own HTTPS API (see `DeviceAPI`).
    case deviceAPI = "device_api"

    public var id: String { rawValue }
    public var displayName: String {
        switch self {
        case .ssh: "SSH"
        case .deviceAPI: "Device API (HTTPS)"
        }
    }
}

public struct ManagedHost: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID = UUID()
    public var name: String
    /// Hostname or IP used for SSH (can also be an alias from ~/.ssh/config).
    public var address: String
    public var port: Int = 22
    public var username: String = "root"
    /// Optional private key path. Empty = use ssh-agent / ~/.ssh/config defaults.
    public var identityFile: String = ""
    /// Run privileged commands through sudo. Uses `sudo -n` when NOPASSWD is configured, otherwise
    /// the host password in the secret store.
    public var useSudo: Bool = false
    /// Allow SSH password / keyboard-interactive login with the password in the secret store
    /// (public keys are still tried first).
    public var passwordLogin: Bool = false
    public var notes: String = ""
    public var lastSeen: Date?
    public var lastDiscovery: [DiscoveredEndpoint] = []
    public var connection: HostConnection = .ssh
    /// Device API: SHA-256 of the self-signed certificate to trust before a publicly trusted one is
    /// installed (any format; separators are ignored). Empty = only system-trusted certificates.
    public var apiPinnedSHA256: String = ""

    public var isDeviceAPI: Bool { connection == .deviceAPI }

    public init(name: String, address: String, port: Int = 22, username: String = "root") {
        self.name = name
        self.address = address
        self.port = port
        self.username = username
    }

    // Tolerant decoding so inventories written by older versions still load.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        address = try c.decode(String.self, forKey: .address)
        port = try c.decodeIfPresent(Int.self, forKey: .port) ?? 22
        username = try c.decodeIfPresent(String.self, forKey: .username) ?? "root"
        identityFile = try c.decodeIfPresent(String.self, forKey: .identityFile) ?? ""
        useSudo = try c.decodeIfPresent(Bool.self, forKey: .useSudo) ?? false
        passwordLogin = try c.decodeIfPresent(Bool.self, forKey: .passwordLogin) ?? false
        notes = try c.decodeIfPresent(String.self, forKey: .notes) ?? ""
        lastSeen = try c.decodeIfPresent(Date.self, forKey: .lastSeen)
        lastDiscovery = (try? c.decodeIfPresent([DiscoveredEndpoint].self, forKey: .lastDiscovery)) ?? []
        connection = (try? c.decodeIfPresent(HostConnection.self, forKey: .connection)) ?? .ssh
        apiPinnedSHA256 = try c.decodeIfPresent(String.self, forKey: .apiPinnedSHA256) ?? ""
    }
}

// MARK: - Certificates

public enum KeyAlgorithm: String, Codable, CaseIterable, Identifiable, Sendable {
    case ecdsaP256 = "ECDSA P-256"
    case ecdsaP384 = "ECDSA P-384"
    case rsa2048 = "RSA 2048"
    case rsa4096 = "RSA 4096"
    public var id: String { rawValue }
}

/// Summary of an X.509 certificate, parsed locally.
public struct CertificateSummary: Codable, Hashable, Sendable {
    public var subject: String
    public var issuer: String
    public var serial: String
    public var notBefore: Date
    public var notAfter: Date
    public var dnsNames: [String]
    /// SHA-256 over the DER encoding, lowercase hex.
    public var sha256: String

    public var daysRemaining: Int {
        Int(floor(notAfter.timeIntervalSinceNow / 86_400))
    }
    public var isExpired: Bool { notAfter < Date() }
}

/// A certificate the app is responsible for issuing and keeping fresh.
public struct ManagedCertificate: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID = UUID()
    public var name: String
    /// First entry is the CN. Wildcards (`*.example.com`) are fine with DNS-01.
    public var domains: [String]
    public var keyAlgorithm: KeyAlgorithm = .ecdsaP256
    /// Overrides the global renewal window when set.
    public var renewDaysBeforeExpiry: Int?
    public var autoRenew: Bool = true

    /// The most recently issued certificate (leaf). The private key lives in the secret store.
    public var current: CertificateSummary?
    public var leafPEM: String?
    public var chainPEM: String?
    public var lastIssued: Date?
    public var lastError: String?
    /// Monitor only: another system (e.g. UniFi OS's own ACME client) renews this certificate.
    /// CertKeeper never issues or deploys it; its deployments just watch what the endpoint serves,
    /// and `current` is the most recently observed certificate.
    public var external: Bool?

    public var isMonitored: Bool { external == true }

    public init(name: String, domains: [String]) {
        self.name = name
        self.domains = domains
    }

    public var fullchainPEM: String? {
        guard let leafPEM else { return nil }
        return leafPEM.trimmingCharacters(in: .whitespacesAndNewlines) + "\n"
            + (chainPEM ?? "").trimmingCharacters(in: .whitespacesAndNewlines) + "\n"
    }
}

// MARK: - Deployments

public enum DeploymentKind: String, Codable, CaseIterable, Identifiable, Sendable {
    case nginx
    case apache
    case proxmox
    case truenas
    case unifiOS
    case opnsense
    /// Pi-hole v6: pihole-FTL's built-in web server (one PEM with key + chain).
    case pihole
    /// Certificate files read by a container (TrueNAS custom app, Docker Compose, …).
    case containerApp
    /// A device with CertKeeper's HTTPS install API (host connection `.deviceAPI`).
    case deviceAPI = "device_api"
    case custom

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .nginx: "nginx"
        case .apache: "Apache httpd"
        case .proxmox: "Proxmox VE"
        case .truenas: "TrueNAS"
        case .unifiOS: "UniFi OS"
        case .opnsense: "OPNsense"
        case .pihole: "Pi-hole"
        case .containerApp: "App (cert files)"
        case .deviceAPI: "Device (HTTPS API)"
        case .custom: "Custom script"
        }
    }

    /// Whether this kind installs to explicit file paths that the user (or discovery) supplies.
    public var usesFilePaths: Bool {
        switch self {
        case .nginx, .apache, .containerApp, .pihole, .custom: true
        default: false
        }
    }
}

/// Places a managed certificate onto a host.
public struct Deployment: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID = UUID()
    public var certificateID: UUID
    public var hostID: UUID
    public var kind: DeploymentKind
    public var certPath: String = ""
    public var keyPath: String = ""
    /// Optional — when set, the leaf goes to certPath and the chain goes here; otherwise certPath gets the full chain.
    public var chainPath: String = ""
    /// TLS endpoint used to verify what the service is actually presenting, e.g. `nas.example.com:443`.
    public var verifyEndpoint: String = ""
    /// nil = use the built-in template for `kind`.
    public var scriptOverride: String?
    public var enabled: Bool = true
    /// Kind-specific settings, exposed to the install script as `CK_OPT_<KEY>` (see `DeploymentOption`).
    public var options: [String: String] = [:]

    /// Fingerprint of the certificate the service was last confirmed to have.
    public var deployedSHA256: String?
    public var deployedNotAfter: Date?
    public var lastDeployed: Date?
    public var lastChecked: Date?
    public var lastError: String?
    /// Redeploy on the next pass even though the leaf fingerprint matches (e.g. the chain was repaired).
    public var forceRedeploy: Bool = false
    /// Whether the live TLS endpoint sends the intermediates clients need (nil = not checked).
    public var servedChainComplete: Bool?
    /// Set when the deployment can't work as configured (e.g. the server's config no longer reads its
    /// files). Automatic deploys skip it until the deployment is edited or a check finds it consistent.
    public var attention: String?

    public init(certificateID: UUID, hostID: UUID, kind: DeploymentKind) {
        self.certificateID = certificateID
        self.hostID = hostID
        self.kind = kind
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        certificateID = try c.decode(UUID.self, forKey: .certificateID)
        hostID = try c.decode(UUID.self, forKey: .hostID)
        kind = try c.decode(DeploymentKind.self, forKey: .kind)
        certPath = try c.decodeIfPresent(String.self, forKey: .certPath) ?? ""
        keyPath = try c.decodeIfPresent(String.self, forKey: .keyPath) ?? ""
        chainPath = try c.decodeIfPresent(String.self, forKey: .chainPath) ?? ""
        verifyEndpoint = try c.decodeIfPresent(String.self, forKey: .verifyEndpoint) ?? ""
        scriptOverride = try c.decodeIfPresent(String.self, forKey: .scriptOverride)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        options = try c.decodeIfPresent([String: String].self, forKey: .options) ?? [:]
        deployedSHA256 = try c.decodeIfPresent(String.self, forKey: .deployedSHA256)
        deployedNotAfter = try c.decodeIfPresent(Date.self, forKey: .deployedNotAfter)
        lastDeployed = try c.decodeIfPresent(Date.self, forKey: .lastDeployed)
        lastChecked = try c.decodeIfPresent(Date.self, forKey: .lastChecked)
        lastError = try c.decodeIfPresent(String.self, forKey: .lastError)
        forceRedeploy = try c.decodeIfPresent(Bool.self, forKey: .forceRedeploy) ?? false
        servedChainComplete = try c.decodeIfPresent(Bool.self, forKey: .servedChainComplete)
        attention = try c.decodeIfPresent(String.self, forKey: .attention)
    }

    public func option(_ key: DeploymentOption) -> String { options[key.rawValue] ?? key.defaultValue }
    public func flag(_ key: DeploymentOption) -> Bool { option(key) == "true" }

    public var isPKCS12: Bool { kind == .containerApp && option(.certFormat) == "pkcs12" }

    /// TrueNAS catalog apps this deployment points at the certificate.
    public var truenasApps: [String] {
        option(.truenasApps).split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}

public enum DeploymentOption: String, Sendable {
    /// TrueNAS: make this the web UI certificate.
    case truenasUI = "truenas_ui"
    /// TrueNAS: comma-separated catalog app names to point at this certificate.
    case truenasApps = "truenas_apps"
    /// Container app: TrueNAS app name, container name or Compose project to restart.
    case restartTarget = "restart_target"
    /// Container app: command to run instead of the automatic restart.
    case reloadCommand = "reload_command"
    /// File-based targets: `chown` installed files to this owner (e.g. `568:568`).
    case fileOwner = "file_owner"
    /// Container app: `pem` (separate cert + key files) or `pkcs12` (one .pfx, e.g. Jellyfin).
    case certFormat = "cert_format"
    /// Container app: password for the .pfx (empty = none).
    case pfxPassword = "pfx_password"
    /// Discovery hint: the host port where the app serves HTTPS.
    case verifyPort = "verify_port"
    /// Pi-hole: set `webserver.domain` to the certificate's first name.
    case piholeSetDomain = "pihole_set_domain"
    /// nginx: config file (-c) of a separate instance; empty = the system nginx.
    case nginxConf = "nginx_conf"
    /// nginx: prefix (-p) of that instance.
    case nginxPrefix = "nginx_prefix"
    /// UniFi OS: folder holding unifi-core.crt/.key (a podman volume on UniFi OS Server).
    case unifiDir = "unifi_dir"

    public var defaultValue: String {
        switch self {
        case .truenasUI: "true"
        case .certFormat: "pem"
        case .piholeSetDomain: "true"
        default: ""
        }
    }

    /// Environment variable name the install script sees.
    public var envName: String { "CK_OPT_" + rawValue.uppercased() }

    /// Options kept in the secret store instead of the inventory file.
    public static let secrets: [DeploymentOption] = [.pfxPassword]
}

// MARK: - Discovery

public struct DiscoveredEndpoint: Codable, Identifiable, Hashable, Sendable {
    public var id: String { "\(kind.rawValue)|\(certPath)|\(label)" }
    public var kind: DeploymentKind
    /// Human-readable context, e.g. nginx server_name or "Web UI".
    public var label: String
    public var certPath: String
    public var keyPath: String
    public var chainPath: String
    public var summary: CertificateSummary?
    /// Deployment options to carry over when adopting (e.g. cert_format, restart_target, verify_port).
    public var options: [String: String]?
    /// Something worth showing next to the endpoint, e.g. "HTTPS is disabled in Jellyfin".
    public var note: String?
}

// MARK: - Activity log

public struct LogEntry: Codable, Identifiable, Hashable, Sendable {
    public enum Level: String, Codable, Sendable { case info, success, warning, error }
    public var id: UUID = UUID()
    public var date: Date = Date()
    public var level: Level
    public var message: String
    public var detail: String?

    public init(_ level: Level, _ message: String, detail: String? = nil) {
        self.level = level
        self.message = message
        self.detail = detail
    }
}

// MARK: - Settings

public struct AppSettings: Codable, Hashable, Sendable {
    public var acmeEmail: String = ""
    public var useStaging: Bool = true
    public var renewDaysBeforeExpiry: Int = 30
    public var checkIntervalHours: Int = 12
    public var autoDeploy: Bool = true
    /// Seconds to wait for the TXT record to appear on public resolvers before giving up.
    public var dnsPropagationTimeout: Int = 300
    public var acceptedTermsOfService: Bool = false
    /// Days to keep activity log entries (nil = the default). Optional so settings saved by earlier
    /// versions, which lack it, still decode.
    public var logRetentionDays: Int?

    public static let defaultLogRetentionDays = 90
    public static let logRetentionRange = 1...365

    public var effectiveLogRetentionDays: Int {
        min(max(logRetentionDays ?? Self.defaultLogRetentionDays, Self.logRetentionRange.lowerBound), Self.logRetentionRange.upperBound)
    }

    public init() {}

    public var directoryURL: URL {
        useStaging
            ? URL(string: "https://acme-staging-v02.api.letsencrypt.org/directory")!
            : URL(string: "https://acme-v02.api.letsencrypt.org/directory")!
    }
}

/// Everything persisted to the inventory file (secrets excluded — those live in the secret store).
public struct Inventory: Codable, Sendable {
    public var hosts: [ManagedHost] = []
    public var certificates: [ManagedCertificate] = []
    public var deployments: [Deployment] = []
    public var settings: AppSettings = AppSettings()
    public var log: [LogEntry] = []
    /// ACME account URL ("kid"), keyed by directory URL.
    public var acmeAccounts: [String: String] = [:]

    public init() {}
}
