# Changelog

## 0.1.0 (2026-03-15)

- Initial release
- Password hashing with PBKDF2-SHA256 (configurable iterations, rehash detection)
- HMAC-SHA256 and HMAC-SHA512 with hex and Base64 output
- Stream checksums for SHA-256, SHA-512, and MD5 (sync and async)
- Consistent hash ring with virtual nodes for key distribution
- Constant-time secure byte comparison
