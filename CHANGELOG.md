# Changelog

## 0.2.0 (2026-03-31)

- Add enhanced password hashing with PBKDF2-SHA512 (v2 format with 256-bit salt, 512-bit hash)
- Add cryptographically secure password generation via PasswordGenerator
- Add hash migration detection for upgrading from v1 to v2 format

## 0.1.9 (2026-03-31)

- Standardize README to 3-badge format with emoji Support section
- Update CI actions to v5 for Node.js 24 compatibility
- Add GitHub issue templates, dependabot config, and PR template

## 0.1.8 (2026-03-26)

- Add Sponsor badge to README
- Fix License section format
- Add trailing period to description

## 0.1.7 (2026-03-23)

- Sync .csproj description with README

## 0.1.6 (2026-03-22)

- Fix changelog formatting

## 0.1.5 (2026-03-22)

- Add dates to changelog entries

## 0.1.4 (2026-03-17)

- Rename Install section to Installation in README per package guide

## 0.1.3 (2026-03-16)

- Add Development section to README
- Add GenerateDocumentationFile, RepositoryType, PackageReadmeFile to .csproj

## 0.1.0 (2026-03-16)

- Initial release
- Password hashing with PBKDF2-SHA256 (configurable iterations, rehash detection)
- HMAC-SHA256 and HMAC-SHA512 with hex and Base64 output
- Stream checksums for SHA-256, SHA-512, and MD5 (sync and async)
- Consistent hash ring with virtual nodes for key distribution
- Constant-time secure byte comparison
