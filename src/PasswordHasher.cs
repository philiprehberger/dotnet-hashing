using System.Security.Cryptography;

namespace Philiprehberger.Hashing;

/// <summary>
/// Password hashing using PBKDF2 (RFC 2898). Produces hashes in the format
/// <c>$pbkdf2$iterations$salt$hash</c>.
/// </summary>
public static class PasswordHasher
{
    /// <summary>
    /// The default number of PBKDF2 iterations.
    /// </summary>
    public const int DefaultIterations = 600_000;

    private const int SaltSize = 16;
    private const int HashSize = 32;

    /// <summary>
    /// Hashes a password using PBKDF2-SHA256 with a cryptographically random salt.
    /// </summary>
    /// <param name="password">The plaintext password to hash.</param>
    /// <param name="iterations">The number of PBKDF2 iterations.</param>
    /// <returns>A string in the format <c>$pbkdf2$iterations$salt$hash</c>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="password"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="iterations"/> is less than 1.</exception>
    public static string Hash(string password, int iterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (iterations < 1)
            throw new ArgumentOutOfRangeException(nameof(iterations), iterations, "Iterations must be at least 1.");

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, HashSize);

        var saltBase64 = Convert.ToBase64String(salt);
        var hashBase64 = Convert.ToBase64String(hash);

        return $"$pbkdf2${iterations}${saltBase64}${hashBase64}";
    }

    /// <summary>
    /// Verifies a password against a previously generated PBKDF2 hash string.
    /// </summary>
    /// <param name="password">The plaintext password to verify.</param>
    /// <param name="hash">The hash string in <c>$pbkdf2$iterations$salt$hash</c> format.</param>
    /// <returns><c>true</c> if the password matches the hash; otherwise <c>false</c>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="password"/> or <paramref name="hash"/> is <c>null</c>.</exception>
    /// <exception cref="FormatException">Thrown when <paramref name="hash"/> is not in the expected format.</exception>
    public static bool Verify(string password, string hash)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(hash);

        var parts = ParseHash(hash);
        var computed = Rfc2898DeriveBytes.Pbkdf2(password, parts.Salt, parts.Iterations, HashAlgorithmName.SHA256, HashSize);

        return CryptographicOperations.FixedTimeEquals(computed, parts.Hash);
    }

    /// <summary>
    /// Checks whether a hash was generated with fewer iterations than the specified minimum
    /// and should be rehashed for stronger security.
    /// </summary>
    /// <param name="hash">The hash string to inspect.</param>
    /// <param name="iterations">The desired minimum number of iterations.</param>
    /// <returns><c>true</c> if the hash uses fewer iterations than <paramref name="iterations"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="hash"/> is <c>null</c>.</exception>
    /// <exception cref="FormatException">Thrown when <paramref name="hash"/> is not in the expected format.</exception>
    public static bool NeedsRehash(string hash, int iterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(hash);

        var parts = ParseHash(hash);
        return parts.Iterations < iterations;
    }

    private static (int Iterations, byte[] Salt, byte[] Hash) ParseHash(string hash)
    {
        var segments = hash.Split('$', StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length != 4 || segments[0] != "pbkdf2")
            throw new FormatException("Hash is not in the expected $pbkdf2$iterations$salt$hash format.");

        if (!int.TryParse(segments[1], out var iterations))
            throw new FormatException("Invalid iteration count in hash.");

        var salt = Convert.FromBase64String(segments[2]);
        var hashBytes = Convert.FromBase64String(segments[3]);

        return (iterations, salt, hashBytes);
    }
}
