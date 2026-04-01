using Xunit;
using Philiprehberger.Hashing;

namespace Philiprehberger.Hashing.Tests;

public class EnhancedHashTests
{
    [Fact]
    public void Hash_Enhanced_ProducesV2Format()
    {
        var hash = Hasher.Password.Hash("password123", useEnhanced: true);
        Assert.StartsWith("$pbkdf2v2$", hash);
    }

    [Fact]
    public void Hash_Default_ProducesV1Format()
    {
        var hash = Hasher.Password.Hash("password123");
        Assert.StartsWith("$pbkdf2$", hash);
    }

    [Fact]
    public void Verify_V2Hash_Succeeds()
    {
        var hash = Hasher.Password.Hash("correcthorse", useEnhanced: true);
        Assert.True(Hasher.Password.Verify("correcthorse", hash));
    }

    [Fact]
    public void Verify_V2Hash_WrongPassword_Fails()
    {
        var hash = Hasher.Password.Hash("correcthorse", useEnhanced: true);
        Assert.False(Hasher.Password.Verify("wrongpassword", hash));
    }

    [Fact]
    public void Verify_AutoDetects_V1AndV2()
    {
        var v1 = Hasher.Password.Hash("test", useEnhanced: false);
        var v2 = Hasher.Password.Hash("test", useEnhanced: true);

        Assert.True(Hasher.Password.Verify("test", v1));
        Assert.True(Hasher.Password.Verify("test", v2));
    }

    [Fact]
    public void NeedsMigration_V1Hash_ReturnsTrue()
    {
        var hash = Hasher.Password.Hash("test", useEnhanced: false);
        Assert.True(Hasher.Password.NeedsMigration(hash));
    }

    [Fact]
    public void NeedsMigration_V2Hash_ReturnsFalse()
    {
        var hash = Hasher.Password.Hash("test", useEnhanced: true);
        Assert.False(Hasher.Password.NeedsMigration(hash));
    }

    [Fact]
    public void NeedsRehash_V2WithLowIterations_ReturnsTrue()
    {
        var hash = Hasher.Password.Hash("test", iterations: 1000, useEnhanced: true);
        Assert.True(Hasher.Password.NeedsRehash(hash, iterations: 600_000));
    }
}
