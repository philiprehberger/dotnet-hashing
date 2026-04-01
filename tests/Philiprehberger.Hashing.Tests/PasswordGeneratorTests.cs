using Xunit;
using Philiprehberger.Hashing;

namespace Philiprehberger.Hashing.Tests;

public class PasswordGeneratorTests
{
    [Fact]
    public void Generate_DefaultLength_Returns16Characters()
    {
        var password = Hasher.Password.Generate();
        Assert.Equal(16, password.Length);
    }

    [Fact]
    public void Generate_CustomLength_ReturnsRequestedLength()
    {
        var password = Hasher.Password.Generate(length: 32);
        Assert.Equal(32, password.Length);
    }

    [Fact]
    public void Generate_LengthTooShort_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Hasher.Password.Generate(length: 5));
    }

    [Fact]
    public void Generate_AllSetsDisabled_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            Hasher.Password.Generate(includeUppercase: false, includeLowercase: false, includeDigits: false, includeSymbols: false));
    }

    [Fact]
    public void Generate_TwoPasswords_AreDifferent()
    {
        var p1 = Hasher.Password.Generate();
        var p2 = Hasher.Password.Generate();
        Assert.NotEqual(p1, p2);
    }

    [Fact]
    public void Generate_UppercaseOnly_ContainsOnlyUppercase()
    {
        var password = Hasher.Password.Generate(length: 20, includeLowercase: false, includeDigits: false, includeSymbols: false);
        Assert.All(password, c => Assert.True(char.IsUpper(c)));
    }
}
