using System.Security.Cryptography;

namespace Philiprehberger.Hashing;

/// <summary>
/// HMAC (Hash-based Message Authentication Code) operations using SHA-256 and SHA-512.
/// </summary>
public static class HmacHasher
{
    /// <summary>
    /// Computes an HMAC-SHA256 of the data using the given key.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>The HMAC-SHA256 as a byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> or <paramref name="data"/> is <c>null</c>.</exception>
    public static byte[] Sha256(byte[] key, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);

        return HMACSHA256.HashData(key, data);
    }

    /// <summary>
    /// Computes an HMAC-SHA256 and returns the result as a lowercase hex string.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>The HMAC-SHA256 as a lowercase hex string.</returns>
    public static string Sha256Hex(byte[] key, byte[] data)
    {
        return Convert.ToHexString(Sha256(key, data)).ToLowerInvariant();
    }

    /// <summary>
    /// Computes an HMAC-SHA256 and returns the result as a Base64 string.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>The HMAC-SHA256 as a Base64 string.</returns>
    public static string Sha256Base64(byte[] key, byte[] data)
    {
        return Convert.ToBase64String(Sha256(key, data));
    }

    /// <summary>
    /// Computes an HMAC-SHA512 of the data using the given key.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>The HMAC-SHA512 as a byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> or <paramref name="data"/> is <c>null</c>.</exception>
    public static byte[] Sha512(byte[] key, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);

        return HMACSHA512.HashData(key, data);
    }

    /// <summary>
    /// Computes an HMAC-SHA512 and returns the result as a lowercase hex string.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>The HMAC-SHA512 as a lowercase hex string.</returns>
    public static string Sha512Hex(byte[] key, byte[] data)
    {
        return Convert.ToHexString(Sha512(key, data)).ToLowerInvariant();
    }

    /// <summary>
    /// Computes an HMAC-SHA512 and returns the result as a Base64 string.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>The HMAC-SHA512 as a Base64 string.</returns>
    public static string Sha512Base64(byte[] key, byte[] data)
    {
        return Convert.ToBase64String(Sha512(key, data));
    }
}
