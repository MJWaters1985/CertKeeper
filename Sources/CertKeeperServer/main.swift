import CertKeeperCore
import Foundation

// ssh runs this binary as its askpass helper (see AskPass): answer and exit before anything else.
let environment = ProcessInfo.processInfo.environment
if environment[AskPass.hostVariable] != nil {
    let prompt = CommandLine.arguments.dropFirst().joined(separator: " ")
    guard let password = AskPass.response(prompt: prompt, environment: environment) else { exit(1) }
    print(password)
    exit(0)
}

do {
    try await Server.run(try ServerConfig(environment: environment))
} catch {
    FileHandle.standardError.write(Data("CertKeeper couldn't start: \(error.localizedDescription)\n".utf8))
    exit(1)
}
