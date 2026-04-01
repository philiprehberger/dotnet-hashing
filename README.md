# Philiprehberger.Hashing

[![CI](https://github.com/philiprehberger/dotnet-hashing/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/dotnet-hashing/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Philiprehberger.Hashing.svg)](https://www.nuget.org/packages/Philiprehberger.Hashing)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/dotnet-hashing)](https://github.com/philiprehberger/dotnet-hashing/commits/main)

Password hashing with PBKDF2-SHA256/SHA512, secure password generation, HMAC, checksums, and consistent hashing.

## Installation

```bash
dotnet add package Philiprehberger.Hashing
```

## Usage

### Password Hashing

```csharp
using Philiprehberger.Hashing;

var hash = Hasher.Password.Hash("my-secret-password");
var isValid = Hasher.Password.Verify("my-secret-password", hash); // true
var needsRehash = Hasher.Password.NeedsRehash(hash);
```

### Enhanced Password Hashing

```csharp
// Use PBKDF2-SHA512 with 256-bit salt and 512-bit hash (v2 format)
var hash = Hasher.Password.Hash("my-secret-password", useEnhanced: true);
var isValid = Hasher.Password.Verify("my-secret-password", hash); // true (auto-detects format)
```

### Password Generation

```csharp
var password = Hasher.Password.Generate();           // 16-char with all character sets
var longer = Hasher.Password.Generate(length: 32);   // 32-char password
var alphanumeric = Hasher.Password.Generate(includeSymbols: false); // no symbols
```

### Hash Migration

```csharp
var oldHash = Hasher.Password.Hash("password");                     // v1 format
var needsMigration = Hasher.Password.NeedsMigration(oldHash);       // true

// Migrate on next login
if (Hasher.Password.Verify("password", oldHash) && Hasher.Password.NeedsMigration(oldHash))
{
    var newHash = Hasher.Password.Hash("password", useEnhanced: true); // v2 format
}
```

### HMAC

```csharp
var key = Encoding.UTF8.GetBytes("my-secret-key");
var data = Encoding.UTF8.GetBytes("message");

var hex = Hasher.Hmac.Sha256Hex(key, data);
var base64 = Hasher.Hmac.Sha256Base64(key, data);
```

### Checksums

```csharp
await using var stream = File.OpenRead("file.zip");
var checksum = await Hasher.Checksum.Sha256Async(stream);
```

### Consistent Hash Ring

```csharp
var ring = new ConsistentHashRing<string>(["server-1", "server-2", "server-3"]);
var server = ring.GetNode("user-123"); // deterministic mapping
```

### Secure Comparison

```csharp
var isEqual = Hasher.SecureEquals(hashA, hashB); // constant-time
```

## API

### `Hasher.Password`

| Method | Description |
|--------|-------------|
| `Hash(string password, int iterations, bool useEnhanced)` | Hash a password using PBKDF2 (v1 SHA-256 or v2 SHA-512) |
| `Verify(string password, string hash)` | Verify a password against a hash (auto-detects format) |
| `NeedsRehash(string hash, int iterations)` | Check if hash needs to be rehashed |
| `NeedsMigration(string hash)` | Check if hash uses v1 format and should migrate to v2 |
| `Generate(int length, bool, bool, bool, bool)` | Generate a cryptographically secure random password |

### `Hasher.Hmac`

| Method | Description |
|--------|-------------|
| `Sha256(byte[] key, byte[] data)` | HMAC-SHA256 as bytes |
| `Sha256Hex(byte[] key, byte[] data)` | HMAC-SHA256 as hex string |
| `Sha256Base64(byte[] key, byte[] data)` | HMAC-SHA256 as Base64 |
| `Sha512(byte[] key, byte[] data)` | HMAC-SHA512 as bytes |

### `Hasher.Checksum`

| Method | Description |
|--------|-------------|
| `Sha256(Stream stream)` | SHA256 checksum as hex |
| `Sha256Async(Stream, CancellationToken)` | Async SHA256 checksum |

### `ConsistentHashRing<T>`

| Method | Description |
|--------|-------------|
| `GetNode(string key)` | Get the node for a key |
| `AddNode(T node)` | Add a node to the ring |
| `RemoveNode(T node)` | Remove a node from the ring |

## Development

```bash
dotnet build src/Philiprehberger.Hashing.csproj --configuration Release
dotnet test tests/Philiprehberger.Hashing.Tests/Philiprehberger.Hashing.Tests.csproj
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/dotnet-hashing)

🐛 [Report issues](https://github.com/philiprehberger/dotnet-hashing/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/dotnet-hashing/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
