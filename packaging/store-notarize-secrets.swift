#!/usr/bin/env swift
// store-notarize-secrets.swift
//
// Stores macOS notarization credentials as generic-password items
// in the login keychain (readable by the `security` CLI tool).
//
// Usage (run from the project root):
//   swift packaging/store-notarize-secrets.swift
//
// To retrieve a secret later in a shell script:
//   security find-generic-password -s "myapp-notarize" -a "APPLE_ID" -w

import Foundation
import Security

// serviceName is set interactively at runtime

// MARK: - Helpers

func readLine(prompt: String) -> String {
    print(prompt, terminator: "")
    fflush(stdout)
    return Swift.readLine(strippingNewline: true) ?? ""
}

func readPassword(prompt: String) -> String {
    if let ptr = getpass(prompt) {
        return String(cString: ptr)
    }
    return ""
}

func storeSecret(account: String, value: String) -> Bool {
    guard let data = value.data(using: .utf8) else { return false }

    // Remove any existing item so we can update cleanly
    let deleteQuery: [CFString: Any] = [
        kSecClass:       kSecClassGenericPassword,
        kSecAttrService: serviceName as CFString,
        kSecAttrAccount: account as CFString,
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    // Store in the login keychain (no entitlement needed, readable by `security` CLI)
    let addQuery: [CFString: Any] = [
        kSecClass:       kSecClassGenericPassword,
        kSecAttrService: serviceName as CFString,
        kSecAttrAccount: account as CFString,
        kSecValueData:   data as CFData,
    ]

    let status = SecItemAdd(addQuery as CFDictionary, nil)
    if status == errSecSuccess {
        print("  ✅  \(account) → stored in login keychain")
        return true
    } else {
        let msg = SecCopyErrorMessageString(status, nil) as String? ?? "unknown error"
        print("  ❌  \(account) failed: \(msg) (OSStatus \(status))")
        return false
    }
}

func expandPath(_ path: String) -> String {
    if path.hasPrefix("~") {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return home + path.dropFirst()
    }
    return path
}

// MARK: - Main

print("""
===========================================================
  macOS Notarization Secrets → Login Keychain
===========================================================
  Items are stored in your login keychain and can be read
  by `security find-generic-password` in any shell script.
  Re-run this script on a new Mac to restore everything.
===========================================================
""")

// Default service name = current directory name (i.e. the project name)
let cwd = FileManager.default.currentDirectoryPath
let defaultService = (cwd as NSString).lastPathComponent + "-notarize"
let serviceInput = readLine(prompt: "\nKeychain service name [\(defaultService)]: ")
let serviceName = serviceInput.isEmpty ? defaultService : serviceInput
print("  → Storing under service: \"\(serviceName)\"\n")


var allOk = true

// ── 1. APPLE_CERTIFICATE_B64 ─────────────────────────────
// Read directly from the .p12 file and base64-encode it here.
print("\n[APPLE_CERTIFICATE_B64]")
let defaultP12 = "~/.ssh/ovc-devid.p12"
let p12Input = readLine(prompt: "  Path to Developer ID .p12 file [\(defaultP12)]: ")
let p12Path = expandPath(p12Input.isEmpty ? defaultP12 : p12Input)

if !FileManager.default.fileExists(atPath: p12Path) {
    print("  ❌  File not found: \(p12Path)")
    allOk = false
} else if let p12Data = FileManager.default.contents(atPath: p12Path) {
    let b64 = p12Data.base64EncodedString()
    if storeSecret(account: "APPLE_CERTIFICATE_B64", value: b64) {
        print("  ℹ️   Encoded \(p12Data.count) bytes from \(p12Path)")
    } else {
        allOk = false
    }
} else {
    print("  ❌  Could not read file: \(p12Path)")
    allOk = false
}

// ── 2. APPLE_CERTIFICATE_PASSWORD ────────────────────────
print("\n[APPLE_CERTIFICATE_PASSWORD]")
let certPass = readPassword(prompt: "  Password used to export the .p12: ")
if certPass.isEmpty {
    print("  ⚠️  Skipped (empty)")
} else {
    if !storeSecret(account: "APPLE_CERTIFICATE_PASSWORD", value: certPass) { allOk = false }
}

// ── 3. APPLE_ID ──────────────────────────────────────────
print("\n[APPLE_ID]")
let appleId = readLine(prompt: "  Apple developer email: ")
if appleId.isEmpty {
    print("  ⚠️  Skipped (empty)")
} else {
    if !storeSecret(account: "APPLE_ID", value: appleId) { allOk = false }
}

// ── 4. APPLE_APP_PASSWORD ─────────────────────────────────
print("\n[APPLE_APP_PASSWORD]")
let appPass = readPassword(prompt: "  App-specific password (from appleid.apple.com): ")
if appPass.isEmpty {
    print("  ⚠️  Skipped (empty)")
} else {
    if !storeSecret(account: "APPLE_APP_PASSWORD", value: appPass) { allOk = false }
}

// ── 5. APPLE_TEAM_ID ──────────────────────────────────────
print("\n[APPLE_TEAM_ID]")
let teamId = readLine(prompt: "  Apple Team ID [FG2QS563CD]: ")
let resolvedTeamId = teamId.isEmpty ? "FG2QS563CD" : teamId
if !storeSecret(account: "APPLE_TEAM_ID", value: resolvedTeamId) { allOk = false }

// ── Done ───────────────────────────────────────────────────
print("""

-----------------------------------------------------------
Done. Verify with:
  security find-generic-password -s "\(serviceName)" -a "APPLE_ID" -w
-----------------------------------------------------------
""")

exit(allOk ? 0 : 1)
