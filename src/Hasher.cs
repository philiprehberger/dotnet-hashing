using System.Security.Cryptography;

namespace Philiprehberger.Hashing;

/// <summary>
/// Static entry point for all hashing operations.
/// </summary>
public static class Hasher
{
    /// <summary>
    /// Password hashing using PBKDF2.
    /// </summary>
    public static class Password
    {
        /// <summary>
        /// Hashes a password using PBKDF2 with a random salt. When <paramref name="useEnhanced"/>
        /// is <c>true</c>, uses SHA-512 with 256-bit salt and 512-bit hash (v2 format).
        /// </summary>
        /// <param name="password">The plaintext password to hash.</param>
        /// <param name="iterations">The number of PBKDF2 iterations (default 600000).</param>
        /// <param name="useEnhanced">When <c>true</c>, uses the enhanced v2 format with SHA-512.</param>
        /// <returns>A hash string in either <c>$pbkdf2$</c> or <c>$pbkdf2v2$</c> format.</returns>
        public static string Hash(string password, int iterations = PasswordHasher.DefaultIterations, bool useEnhanced = false)
            => useEnhanced
                ? EnhancedPasswordHasher.Hash(password, iterations)
                : PasswordHasher.Hash(password, iterations);

        /// <summary>
        /// Verifies a password against a previously generated hash. Automatically detects
        /// whether the hash uses v1 or v2 format.
        /// </summary>
        /// <param name="password">The plaintext password to verify.</param>
        /// <param name="hash">The hash string to verify against.</param>
        /// <returns><c>true</c> if the password matches the hash; otherwise <c>false</c>.</returns>
        public static bool Verify(string password, string hash)
            => hash.StartsWith("$pbkdf2v2$", StringComparison.Ordinal)
                ? EnhancedPasswordHasher.Verify(password, hash)
                : PasswordHasher.Verify(password, hash);

        /// <summary>
        /// Checks whether a hash was generated with fewer iterations than the current default
        /// and should be rehashed.
        /// </summary>
        /// <param name="hash">The hash string to inspect.</param>
        /// <param name="iterations">The desired minimum iterations (default 600000).</param>
        /// <returns><c>true</c> if the hash uses fewer iterations than specified.</returns>
        public static bool NeedsRehash(string hash, int iterations = PasswordHasher.DefaultIterations)
            => hash.StartsWith("$pbkdf2v2$", StringComparison.Ordinal)
                ? EnhancedPasswordHasher.NeedsRehash(hash, iterations)
                : PasswordHasher.NeedsRehash(hash, iterations);

        /// <summary>
        /// Returns <c>true</c> if the hash uses the older v1 format and should be migrated to v2.
        /// </summary>
        /// <param name="hash">The hash string to inspect.</param>
        /// <returns><c>true</c> if the hash uses the v1 <c>$pbkdf2$</c> format.</returns>
        public static bool NeedsMigration(string hash)
            => hash.StartsWith("$pbkdf2$", StringComparison.Ordinal);

        /// <summary>
        /// Generates a cryptographically secure random password.
        /// </summary>
        /// <param name="length">The length of the password. Must be at least 8.</param>
        /// <param name="includeUppercase">Whether to include uppercase letters.</param>
        /// <param name="includeLowercase">Whether to include lowercase letters.</param>
        /// <param name="includeDigits">Whether to include digits.</param>
        /// <param name="includeSymbols">Whether to include symbols.</param>
        /// <returns>A randomly generated password string.</returns>
        public static string Generate(
            int length = 16,
            bool includeUppercase = true,
            bool includeLowercase = true,
            bool includeDigits = true,
            bool includeSymbols = true)
            => PasswordGenerator.Generate(length, includeUppercase, includeLowercase, includeDigits, includeSymbols);
    }

    /// <summary>
    /// HMAC-based message authentication.
    /// </summary>
    public static class Hmac
    {
        /// <summary>
        /// Computes an HMAC-SHA256 of the data using the given key.
        /// </summary>
        public static byte[] Sha256(byte[] key, byte[] data)
            => HmacHasher.Sha256(key, data);

        /// <summary>
        /// Computes an HMAC-SHA256 and returns the result as a lowercase hex string.
        /// </summary>
        public static string Sha256Hex(byte[] key, byte[] data)
            => HmacHasher.Sha256Hex(key, data);

        /// <summary>
        /// Computes an HMAC-SHA256 and returns the result as a Base64 string.
        /// </summary>
        public static string Sha256Base64(byte[] key, byte[] data)
            => HmacHasher.Sha256Base64(key, data);

        /// <summary>
        /// Computes an HMAC-SHA512 of the data using the given key.
        /// </summary>
        public static byte[] Sha512(byte[] key, byte[] data)
            => HmacHasher.Sha512(key, data);

        /// <summary>
        /// Computes an HMAC-SHA512 and returns the result as a lowercase hex string.
        /// </summary>
        public static string Sha512Hex(byte[] key, byte[] data)
            => HmacHasher.Sha512Hex(key, data);

        /// <summary>
        /// Computes an HMAC-SHA512 and returns the result as a Base64 string.
        /// </summary>
        public static string Sha512Base64(byte[] key, byte[] data)
            => HmacHasher.Sha512Base64(key, data);
    }

    /// <summary>
    /// File and stream checksum operations.
    /// </summary>
    public static class Checksum
    {
        /// <summary>
        /// Computes a SHA-256 checksum of the stream.
        /// </summary>
        public static string Sha256(Stream stream)
            => ChecksumHasher.Sha256(stream);

        /// <summary>
        /// Asynchronously computes a SHA-256 checksum of the stream.
        /// </summary>
        public static Task<string> Sha256Async(Stream stream, CancellationToken ct = default)
            => ChecksumHasher.Sha256Async(stream, ct);

        /// <summary>
        /// Computes a SHA-512 checksum of the stream.
        /// </summary>
        public static string Sha512(Stream stream)
            => ChecksumHasher.Sha512(stream);

        /// <summary>
        /// Asynchronously computes a SHA-512 checksum of the stream.
        /// </summary>
        public static Task<string> Sha512Async(Stream stream, CancellationToken ct = default)
            => ChecksumHasher.Sha512Async(stream, ct);

        /// <summary>
        /// Computes an MD5 checksum of the stream. Prefer SHA-256 for security-sensitive use.
        /// </summary>
        [Obsolete("MD5 is cryptographically broken. Use Sha256 or Sha512 for security-sensitive checksums.")]
        public static string Md5(Stream stream)
            => ChecksumHasher.Md5(stream);

        /// <summary>
        /// Asynchronously computes an MD5 checksum of the stream. Prefer SHA-256 for security-sensitive use.
        /// </summary>
        [Obsolete("MD5 is cryptographically broken. Use Sha256Async or Sha512Async for security-sensitive checksums.")]
        public static Task<string> Md5Async(Stream stream, CancellationToken ct = default)
            => ChecksumHasher.Md5Async(stream, ct);
    }

    /// <summary>
    /// Performs a constant-time comparison of two byte arrays to prevent timing attacks.
    /// </summary>
    /// <param name="a">The first byte array.</param>
    /// <param name="b">The second byte array.</param>
    /// <returns><c>true</c> if both arrays have the same length and contents; otherwise <c>false</c>.</returns>
    public static bool SecureEquals(byte[] a, byte[] b)
    {
        return CryptographicOperations.FixedTimeEquals(a, b);
    }
}
