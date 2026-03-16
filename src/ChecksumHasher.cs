using System.Security.Cryptography;

namespace Philiprehberger.Hashing;

/// <summary>
/// Stream checksum operations using SHA-256, SHA-512, and MD5.
/// </summary>
public static class ChecksumHasher
{
    /// <summary>
    /// Computes a SHA-256 checksum of the stream.
    /// </summary>
    /// <param name="stream">The stream to hash.</param>
    /// <returns>The SHA-256 hash as a lowercase hex string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is <c>null</c>.</exception>
    public static string Sha256(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Asynchronously computes a SHA-256 checksum of the stream.
    /// </summary>
    /// <param name="stream">The stream to hash.</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>The SHA-256 hash as a lowercase hex string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is <c>null</c>.</exception>
    public static async Task<string> Sha256Async(Stream stream, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Computes a SHA-512 checksum of the stream.
    /// </summary>
    /// <param name="stream">The stream to hash.</param>
    /// <returns>The SHA-512 hash as a lowercase hex string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is <c>null</c>.</exception>
    public static string Sha512(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var hash = SHA512.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Asynchronously computes a SHA-512 checksum of the stream.
    /// </summary>
    /// <param name="stream">The stream to hash.</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>The SHA-512 hash as a lowercase hex string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is <c>null</c>.</exception>
    public static async Task<string> Sha512Async(Stream stream, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var hash = await SHA512.HashDataAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Computes an MD5 checksum of the stream. Prefer SHA-256 for security-sensitive use.
    /// </summary>
    /// <param name="stream">The stream to hash.</param>
    /// <returns>The MD5 hash as a lowercase hex string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is <c>null</c>.</exception>
    [Obsolete("MD5 is cryptographically broken. Use Sha256 or Sha512 for security-sensitive checksums.")]
    public static string Md5(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        #pragma warning disable CA5351 // Do not use broken cryptographic algorithms
        var hash = MD5.HashData(stream);
        #pragma warning restore CA5351
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Asynchronously computes an MD5 checksum of the stream. Prefer SHA-256 for security-sensitive use.
    /// </summary>
    /// <param name="stream">The stream to hash.</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>The MD5 hash as a lowercase hex string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="stream"/> is <c>null</c>.</exception>
    [Obsolete("MD5 is cryptographically broken. Use Sha256Async or Sha512Async for security-sensitive checksums.")]
    public static async Task<string> Md5Async(Stream stream, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        #pragma warning disable CA5351 // Do not use broken cryptographic algorithms
        var hash = await MD5.HashDataAsync(stream, ct).ConfigureAwait(false);
        #pragma warning restore CA5351
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
