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
        /// Hashes a password using PBKDF2 with a random salt.
        /// </summary>
        /// <param name="password">The plaintext password to hash.</param>
        /// <param name="iterations">The number of PBKDF2 iterations (default 600000).</param>
        /// <returns>A string in the format <c>$pbkdf2$iterations$salt$hash</c>.</returns>
        public static string Hash(string password, int iterations = PasswordHasher.DefaultIterations)
            => PasswordHasher.Hash(password, iterations);

        /// <summary>
        /// Verifies a password against a previously generated hash.
        /// </summary>
        /// <param name="password">The plaintext password to verify.</param>
        /// <param name="hash">The hash string to verify against.</param>
        /// <returns><c>true</c> if the password matches the hash; otherwise <c>false</c>.</returns>
        public static bool Verify(string password, string hash)
            => PasswordHasher.Verify(password, hash);

        /// <summary>
        /// Checks whether a hash was generated with fewer iterations than the current default
        /// and should be rehashed.
        /// </summary>
        /// <param name="hash">The hash string to inspect.</param>
        /// <param name="iterations">The desired minimum iterations (default 600000).</param>
        /// <returns><c>true</c> if the hash uses fewer iterations than specified.</returns>
        public static bool NeedsRehash(string hash, int iterations = PasswordHasher.DefaultIterations)
            => PasswordHasher.NeedsRehash(hash, iterations);
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
