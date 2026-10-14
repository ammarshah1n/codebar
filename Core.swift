import Foundation
import CryptoKit
import Security
import Darwin

struct CodesError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
    init(_ message: String) { self.message = message }
}

struct OTPAccount: Codable, Identifiable {
    let id: UUID
    let name: String
    let issuer: String
    let secret: Data
    let algorithm: String
    let digits: Int
    let period: Int

    func validate() throws {
        guard !secret.isEmpty, secret.count <= 1024, ["SHA1", "SHA256", "SHA512"].contains(algorithm),
              [6, 7, 8].contains(digits), period == 30, name.count <= 1024, issuer.count <= 1024 else {
            throw CodesError("Unsupported or damaged account. Nothing was imported.")
        }
    }

    func code(at date: Date = Date()) -> String {
        guard (try? validate()) != nil, date.timeIntervalSince1970 >= 0,
              date.timeIntervalSince1970 < Double(Int64.max) else { return "------" }
        var counter = UInt64(date.timeIntervalSince1970 / Double(period)).bigEndian
        let message = withUnsafeBytes(of: &counter) { Data($0) }
        let key = SymmetricKey(data: secret)
        let digest: [UInt8]
        switch algorithm {
        case "SHA256": digest = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case "SHA512": digest = Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        default: digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        }
        let offset = Int(digest.last! & 15)
        let number = digest[offset..<offset+4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } & 0x7fffffff
        let modulus: UInt32 = digits == 8 ? 100_000_000 : (digits == 7 ? 10_000_000 : 1_000_000)
        let value = String(number % modulus)
        return String(repeating: "0", count: digits - value.count) + value
    }
}

struct Transfer {
    let accounts: [OTPAccount]
    let batchSize: Int
    let batchIndex: Int
}

// Bounded protobuf wire reader: reject truncation, overflow and unexpected wire types.
private struct Proto {
    var bytes: [UInt8]
    var position = 0
    init(_ data: Data) { bytes = Array(data) }
    mutating func varint() throws -> UInt64 {
        var value: UInt64 = 0
        for n in 0..<10 {
            guard position < bytes.count else { throw CodesError("Truncated transfer QR.") }
            let byte = bytes[position]; position += 1
            guard n < 9 || byte < 2 else { throw CodesError("Invalid transfer number.") }
            value |= UInt64(byte & 127) << (n * 7)
            if byte & 128 == 0 { return value }
        }
        throw CodesError("Invalid transfer number.")
    }
    mutating func take(_ length: UInt64) throws -> Data {
        guard length <= UInt64(bytes.count - position) else { throw CodesError("Truncated transfer QR.") }
        let end = position + Int(length)
        defer { position = end }
        return Data(bytes[position..<end])
    }
    mutating func fields() throws -> [Int: [(Int, Data, UInt64)]] {
        var result: [Int: [(Int, Data, UInt64)]] = [:]
        while position < bytes.count {
            let tag = try varint()
            guard tag >> 3 > 0, tag >> 3 <= 536870911 else { throw CodesError("Invalid transfer field.") }
            let field = Int(tag >> 3), wire = Int(tag & 7)
            var data = Data(), number: UInt64 = 0
            switch wire {
            case 0: number = try varint()
            case 1: data = try take(8)
            case 2: let length = try varint(); data = try take(length)
            case 5: data = try take(4)
            default: throw CodesError("Unsupported transfer encoding.")
            }
            result[field, default: []].append((wire, data, number))
        }
        return result
    }
}

enum Importer {
    static func parse(_ text: String) throws -> Transfer {
        guard text.utf8.count <= 1_000_000,
              let url = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              url.scheme == "otpauth-migration", url.host == "offline",
              let values = url.queryItems?.filter({ $0.name == "data" }), values.count == 1,
              var encoded = values.first?.value else {
            throw CodesError("Use a Google Authenticator Export accounts QR, not an ordinary setup QR.")
        }
        encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        guard let data = Data(base64Encoded: encoded), data.count <= 500_000 else { throw CodesError("Invalid transfer data.") }
        var reader = Proto(data)
        let fields = try reader.fields()
        func number(_ fields: [Int: [(Int, Data, UInt64)]], _ key: Int, default fallback: UInt64 = 0) throws -> UInt64 {
            guard let values = fields[key] else { return fallback }
            guard values.count == 1, values[0].0 == 0 else { throw CodesError("Invalid transfer metadata.") }
            return values[0].2
        }
        let version = try number(fields, 2)
        let size = try number(fields, 3, default: 1)
        let index = try number(fields, 4)
        guard [UInt64(1), 2].contains(version), size >= 1, size <= 1000, index < size,
              let records = fields[1], !records.isEmpty, records.count <= 1000 else {
            throw CodesError("Unsupported or empty transfer. Export again from Google Authenticator.")
        }
        let accounts = try records.map { record -> OTPAccount in
            guard record.0 == 2 else { throw CodesError("Invalid account record.") }
            var parser = Proto(record.1)
            let values = try parser.fields()
            func bytes(_ key: Int, required: Bool = false) throws -> Data {
                guard let entries = values[key] else {
                    if required { throw CodesError("Account secret missing.") }
                    return Data()
                }
                guard entries.count == 1, entries[0].0 == 2 else { throw CodesError("Invalid account field.") }
                return entries[0].1
            }
            let secret = try bytes(1, required: true)
            guard let name = String(data: try bytes(2), encoding: .utf8),
                  let issuer = String(data: try bytes(3), encoding: .utf8) else { throw CodesError("Invalid account label.") }
            let algorithm = try number(values, 4), digits = try number(values, 5), type = try number(values, 6)
            guard type == 2 else { throw CodesError("This transfer contains a counter-based or unsupported account. Export time-based accounts separately; nothing was imported.") }
            guard let algo = [UInt64(1): "SHA1", 2: "SHA256", 3: "SHA512"][algorithm],
                  let count = [UInt64(1): 6, 2: 8, 3: 7][digits] else { throw CodesError("Unsupported code format. Nothing was imported.") }
            let account = OTPAccount(id: UUID(), name: name, issuer: issuer, secret: secret, algorithm: algo, digits: count, period: 30)
            try account.validate()
            return account
        }
        return Transfer(accounts: accounts, batchSize: Int(size), batchIndex: Int(index))
    }
}

final class CodeStore {
    private let service: String
    init(service: String = "io.github.ammarshah1n.codebar") { self.service = service }
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: "accounts", kSecAttrSynchronizable as String: false]
    }
    func load() throws -> [OTPAccount] {
        var request = query
        // A denied/stale signing identity must show an error, not hang startup behind an invisible Keychain prompt.
        request[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let data = result as? Data else { throw CodesError("Keychain is unavailable (\(status)). Unlock your Mac and retry. Existing accounts were not changed.") }
        do {
            let accounts = try JSONDecoder().decode([OTPAccount].self, from: data)
            for account in accounts { try account.validate() }
            return accounts
        } catch { throw CodesError("Stored accounts could not be read. Import is blocked to protect existing data.") }
    }
    func merge(_ incoming: [OTPAccount]) throws -> Int {
        guard !incoming.isEmpty else { throw CodesError("No accounts to import.") }
        // Serialize the entire read/merge/write across windows AND processes.
        // This file contains no secrets; the actual data stays in Keychain.
        let folder = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let fd = Darwin.open(folder.appendingPathComponent("codebar-import.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw CodesError("Could not protect the import transaction. Nothing was changed.") }
        defer { Darwin.close(fd) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw CodesError("Another import is in progress. Retry in a moment.") }
        defer { flock(fd, LOCK_UN) }
        var accounts = try load()
        let previousCount = accounts.count
        for account in incoming {
            try account.validate()
            if !accounts.contains(where: { $0.secret == account.secret && $0.algorithm == account.algorithm && $0.digits == account.digits && $0.period == account.period && $0.name == account.name && $0.issuer == account.issuer }) { accounts.append(account) }
        }
        let data = try JSONEncoder().encode(accounts)
        let update = [kSecValueData as String: data]
        var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var addition = query
            addition[kSecValueData as String] = data
            // macOS login Keychain governs access; do not claim iOS Data Protection guarantees.
            status = SecItemAdd(addition as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw CodesError("Could not save to Keychain (\(status)). Nothing was replaced or deleted. Retry after unlocking your Mac.") }
        return accounts.count - previousCount
    }
}

func runSelfTests() throws {
    func check(_ truth: @autoclosure () throws -> Bool, _ label: String) throws {
        guard try truth() else { throw CodesError("Self-test failed: \(label)") }
    }
    let times: [TimeInterval] = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
    let vectors = [
        ("SHA1", "12345678901234567890", ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]),
        ("SHA256", "12345678901234567890123456789012", ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"]),
        ("SHA512", "1234567890123456789012345678901234567890123456789012345678901234", ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"])
    ]
    for (algo, secret, expected) in vectors {
        let account = OTPAccount(id: UUID(), name: "Synthetic", issuer: "Test", secret: Data(secret.utf8), algorithm: algo, digits: 8, period: 30)
        for (index, time) in times.enumerated() { try check(account.code(at: Date(timeIntervalSince1970: time)) == expected[index], "RFC6238 \(algo) \(index)") }
    }
    func varint(_ x: UInt64) -> Data {
        var value = x, data = Data()
        repeat { let byte = UInt8(value & 127); value >>= 7; data.append(byte | (value > 0 ? 128 : 0)) } while value > 0
        return data
    }
    func blob(_ field: UInt64, _ data: Data) -> Data { varint(field * 8 + 2) + varint(UInt64(data.count)) + data }
    func num(_ field: UInt64, _ value: UInt64) -> Data { varint(field * 8) + varint(value) }
    func url(_ data: Data) -> String {
        var parts = URLComponents(); parts.scheme = "otpauth-migration"; parts.host = "offline"
        parts.queryItems = [URLQueryItem(name: "data", value: data.base64EncodedString())]
        return parts.string!
    }
    let record = blob(1, Data("12345678901234567890".utf8)) + blob(2, Data("Synthetic".utf8)) + num(4, 1) + num(5, 1) + num(6, 2)
    let payload = blob(1, record) + num(2, 1) + num(3, 2) + num(4, 1)
    let parsed = try Importer.parse(url(payload))
    let v2 = try Importer.parse(url(blob(1, record) + num(2, 2) + num(3, 2) + num(4, 0)))
    try check(v2.accounts.count == 1 && v2.batchIndex == 0 && v2.batchSize == 2, "Google v2 transfer")
    try check(v2.accounts[0].code(at: Date(timeIntervalSince1970: 59)) == "287082", "Google v2 code")
    try check(parsed.accounts.count == 1 && parsed.batchSize == 2 && parsed.batchIndex == 1, "Google transfer batch")
    try check(parsed.accounts[0].code(at: Date(timeIntervalSince1970: 59)) == "287082", "Google transfer code")
    let broken = [Data(payload.dropLast()), payload + Data([0x80]), Data([0x0a, 0xff, 0xff]), blob(1, record + num(6, 1)) + num(2, 1), blob(1, record) + num(2, 99)]
    for item in broken {
        var failed = false
        do { _ = try Importer.parse(url(item)) } catch { failed = true }
        try check(failed, "Malformed transfer rejection")
    }
    // Fresh random namespace: never touches the user's actual accounts.
    let service = "io.github.ammarshah1n.codebar.selftest." + UUID().uuidString
    let store = CodeStore(service: service)
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "accounts"]
    defer { SecItemDelete(query as CFDictionary) }
    try check(try store.load().isEmpty, "New Keychain")
    try check(try store.merge(parsed.accounts) == 1, "Keychain write")
    try check(try CodeStore(service: service).load()[0].secret == parsed.accounts[0].secret, "Keychain reload")
    try check(try store.merge(parsed.accounts) == 0, "Idempotent reimport")
    let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: Data("damaged test data".utf8)] as CFDictionary)
    try check(status == errSecSuccess, "Corruption fixture")
    var blocked = false
    do { _ = try store.merge(parsed.accounts) } catch { blocked = true }
    try check(blocked, "Corrupt store not overwritten")
    print("PASS: 18 RFC6238 vectors; Google transfer/batch; malformed input; Keychain save/reload/deduplication; corruption fail-closed.")
}
