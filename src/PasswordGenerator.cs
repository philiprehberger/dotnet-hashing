using System.Security.Cryptography;

namespace Philiprehberger.Hashing;

/// <summary>
/// Generates cryptographically secure random passwords using
/// <see cref="RandomNumberGenerator"/> for entropy.
/// </summary>
public static class PasswordGenerator
{
    private const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
    private const string Digits = "0123456789";
    private const string Symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    /// <summary>
    /// Generates a cryptographically secure random password.
    /// </summary>
    /// <param name="length">The length of the password to generate. Must be at least 8.</param>
    /// <param name="includeUppercase">Whether to include uppercase letters.</param>
    /// <param name="includeLowercase">Whether to include lowercase letters.</param>
    /// <param name="includeDigits">Whether to include digits.</param>
    /// <param name="includeSymbols">Whether to include symbols.</param>
    /// <returns>A randomly generated password string.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="length"/> is less than 8.</exception>
    /// <exception cref="ArgumentException">Thrown when all character sets are disabled.</exception>
    public static string Generate(
        int length = 16,
        bool includeUppercase = true,
        bool includeLowercase = true,
        bool includeDigits = true,
        bool includeSymbols = true)
    {
        if (length < 8)
            throw new ArgumentOutOfRangeException(nameof(length), length, "Password length must be at least 8.");

        var charPool = BuildCharPool(includeUppercase, includeLowercase, includeDigits, includeSymbols);

        if (charPool.Length == 0)
            throw new ArgumentException("At least one character set must be included.");

        var result = new char[length];
        FillRandom(result, charPool);

        EnsureRequiredCharacters(result, includeUppercase, includeLowercase, includeDigits, includeSymbols);

        return new string(result);
    }

    private static string BuildCharPool(bool uppercase, bool lowercase, bool digits, bool symbols)
    {
        var pool = "";
        if (uppercase) pool += Uppercase;
        if (lowercase) pool += Lowercase;
        if (digits) pool += Digits;
        if (symbols) pool += Symbols;
        return pool;
    }

    private static void FillRandom(char[] result, string charPool)
    {
        var bytes = RandomNumberGenerator.GetBytes(result.Length);
        for (var i = 0; i < result.Length; i++)
        {
            result[i] = charPool[bytes[i] % charPool.Length];
        }
    }

    private static void EnsureRequiredCharacters(
        char[] result,
        bool includeUppercase,
        bool includeLowercase,
        bool includeDigits,
        bool includeSymbols)
    {
        var requiredSets = new List<string>();
        if (includeUppercase) requiredSets.Add(Uppercase);
        if (includeLowercase) requiredSets.Add(Lowercase);
        if (includeDigits) requiredSets.Add(Digits);
        if (includeSymbols) requiredSets.Add(Symbols);

        if (requiredSets.Count == 0)
            return;

        var positionBytes = RandomNumberGenerator.GetBytes(requiredSets.Count);
        var charBytes = RandomNumberGenerator.GetBytes(requiredSets.Count);

        for (var i = 0; i < requiredSets.Count; i++)
        {
            var set = requiredSets[i];
            if (!ContainsAny(result, set))
            {
                var position = positionBytes[i] % result.Length;
                result[position] = set[charBytes[i] % set.Length];
            }
        }
    }

    private static bool ContainsAny(char[] result, string characterSet)
    {
        foreach (var c in result)
        {
            if (characterSet.Contains(c))
                return true;
        }

        return false;
    }
}
