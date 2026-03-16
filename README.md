# Philiprehberger.Hashing

Convenient, secure hashing API — password hashing, HMAC, checksums, and consistent hashing.

## Install

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
| `Hash(string password)` | Hash a password using PBKDF2 |
| `Verify(string password, string hash)` | Verify a password against a hash |
| `NeedsRehash(string hash)` | Check if hash needs to be rehashed |

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

## License

MIT
