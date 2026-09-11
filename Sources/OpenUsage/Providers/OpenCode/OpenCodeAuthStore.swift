import Foundation

/// Reads the OpenCode credentials already on the machine. Local-only — never the network. The
/// `opencode-go` key is both the first-run detection signal and the Bearer token for
/// `GET /zen/go/v1/usage`, so it lives behind one loader.
///
/// OpenCode 2 moved credentials from `auth.json` (`{"opencode-go":{"key":"sk-..."}}`) into the SQLite
/// `credential` table (`integration_id='opencode-go'`, `value` JSON `{"type":"key","key":"sk-..."}`).
/// This store reads the file first for backwards compatibility, then falls back to the `credential`
/// table across all `opencode*.db` files, so both OpenCode 1 and OpenCode 2 are covered.
struct OpenCodeAuthStore: Sendable {
    var files: TextFileAccessing
    var environment: EnvironmentReading
    var homeDirectory: @Sendable () -> URL
    var sqlite: SQLiteAccessing
    var databasePaths: @Sendable () throws -> [String]

    /// OpenCode 2 `credential`-table lookups. The Go-key fallback tries `opencode-go`, then `opencode`
    /// — scoped to those two IDs so a BYO key (e.g. OpenAI) can never be mistaken for Go auth and sent
    /// to the usage endpoint as a Bearer token.
    static let credentialSQLGoKey =
        "SELECT json_extract(value,'$.key') FROM credential WHERE integration_id = 'opencode-go' AND json_extract(value,'$.key') LIKE 'sk-%' LIMIT 1;"
    static let credentialSQLOpencodeKey =
        "SELECT json_extract(value,'$.key') FROM credential WHERE integration_id = 'opencode' AND json_extract(value,'$.key') LIKE 'sk-%' LIMIT 1;"
    static let credentialSQLCodexOAuth =
        "SELECT value FROM credential WHERE integration_id = 'openai' AND json_extract(value,'$.type') = 'oauth' LIMIT 1;"

    init(
        files: TextFileAccessing = LocalTextFileAccessor(),
        environment: EnvironmentReading = ProcessEnvironmentReader(),
        homeDirectory: @escaping @Sendable () -> URL = { FileManager.default.homeDirectoryForCurrentUser },
        sqlite: SQLiteAccessing = SQLiteCLIAccessor(),
        databasePaths: (@Sendable () throws -> [String])? = nil
    ) {
        self.files = files
        self.environment = environment
        self.homeDirectory = homeDirectory
        self.sqlite = sqlite
        if let databasePaths {
            self.databasePaths = databasePaths
        } else {
            let env = environment
            let home = homeDirectory
            self.databasePaths = {
                let dir = OpenCodePaths.dataDirectory(environment: env, homeDirectory: home())
                return try OpenCodePaths.databaseFiles(in: dir)
            }
        }
    }

    var dataDirectory: String {
        OpenCodePaths.dataDirectory(environment: environment, homeDirectory: homeDirectory())
    }

    var authFilePath: String {
        OpenCodePaths.authFilePath(dataDirectory: dataDirectory)
    }

    /// The non-empty `opencode-go` API key, or `nil` when the user has not logged into OpenCode Go.
    /// Reads `auth.json` first (OpenCode 1), then falls back to the SQLite `credential` table
    /// (OpenCode 2, `integration_id='opencode-go'` with `value` JSON `{"type":"key","key":"sk-..."}`).
    /// Reads only that one entry — tolerant of unrelated sibling entries (other providers, or a future
    /// non-object field like a schema marker) so one odd value can't hide a valid key. A present file
    /// that can't be read or parsed throws `credentialsUnreadable` so broken storage is never mistaken
    /// for logout; an absent file, or a file without the entry, falls through to the database.
    func goAPIKey() throws -> String? {
        if let object = try authObject(),
           let entry = object["opencode-go"] as? [String: Any],
           let key = entry["key"] as? String,
           let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty {
            return trimmed
        }
        for sql in [Self.credentialSQLGoKey, Self.credentialSQLOpencodeKey] {
            if let key = credentialValue(from: sql) {
                return key
            }
        }
        return nil
    }

    /// Whether OpenCode's `openai` provider is currently authenticated through the built-in ChatGPT /
    /// Codex OAuth flow. OpenCode stores API-key and OAuth credentials under the same provider key, so
    /// checking the auth type is required before attributing its `providerID = openai` database rows to
    /// the Codex card. Secrets stay inside the auth boundary and are never returned or logged.
    func hasCodexOAuth() throws -> Bool {
        if let entry = try authObject()?["openai"] as? [String: Any], Self.isCodexOAuth(entry) {
            return true
        }
        guard let value = credentialValue(from: Self.credentialSQLCodexOAuth),
              let data = value.data(using: .utf8),
              let entry = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return false }
        return Self.isCodexOAuth(entry)
    }

    /// One OAuth entry is enough — OpenCode writes both fields, but a refresh-only or access-only row
    /// still proves the OAuth flow rather than an API key.
    private static func isCodexOAuth(_ entry: [String: Any]) -> Bool {
        guard entry["type"] as? String == "oauth" else { return false }
        return ["access", "refresh"].contains { field in
            ((entry[field] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty) != nil
        }
    }

    /// `auth.json` as a JSON object, or `nil` when the file is absent. A present file that can't be
    /// read or parsed throws `credentialsUnreadable`.
    private func authObject() throws -> [String: Any]? {
        let text: String?
        do {
            text = try files.readTextIfPresent(authFilePath)
        } catch {
            throw OpenCodeUsageError.credentialsUnreadable(detail: error.localizedDescription)
        }
        guard let text else { return nil }
        guard let data = text.data(using: .utf8),
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            throw OpenCodeUsageError.credentialsUnreadable(detail: "auth.json is not valid JSON")
        }
        return object
    }

    /// Best-effort lookup across all `opencode*.db` files. Missing tables read as "not stored there";
    /// anything else that fails is logged, since the Codex scanner exits at its auth guard and would
    /// otherwise drop usage silently. Never throws — the Go path reports the scanner's `databaseUnreadable`.
    private func credentialValue(from sql: String) -> String? {
        let paths: [String]
        do {
            paths = try databasePaths()
        } catch {
            AppLog.warn(LogTag.plugin("opencode"), "credential lookup skipped: data directory unreadable: \(error.localizedDescription)")
            return nil
        }
        for path in paths {
            do {
                if let value = try sqlite.queryValue(path: path, sql: sql)?
                    .trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty {
                    return value
                }
            } catch {
                // Pre-OpenCode-2 databases have no `credential` table — expected, not an error.
                if error.localizedDescription.contains("no such table") { continue }
                AppLog.warn(LogTag.plugin("opencode"), "credential lookup failed for \(path): \(error.localizedDescription)")
                continue
            }
        }
        return nil
    }
}
