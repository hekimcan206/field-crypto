using System.Security.Cryptography;
using FieldCrypto.Kms;

namespace FieldCrypto.UnitTests;

public sealed class LocalKmsTests
{
    private static readonly KeyWrapContext Context = new(Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8057"), "data");

    [Fact]
    public void Rotation_changes_the_wrapping_version_and_old_versions_still_unwrap()
    {
        var kms = LocalKeyEncryptionService.CreateEphemeral();
        var key = RandomNumberGenerator.GetBytes(32);

        var v1 = kms.Wrap(key, Context);
        kms.Rotate().Should().Be("2");
        var v2 = kms.Wrap(key, Context);

        v1.KeyVersion.Should().Be("1");
        v2.KeyVersion.Should().Be("2");
        kms.Unwrap(v1.Ciphertext, Context).Should().Equal(key);
        kms.Unwrap(v2.Ciphertext, Context).Should().Equal(key);
    }

    [Fact]
    public void Unwrap_checks_the_associated_data()
    {
        var kms = LocalKeyEncryptionService.CreateEphemeral();
        var wrapped = kms.Wrap(RandomNumberGenerator.GetBytes(32), Context);

        var otherId = () => kms.Unwrap(wrapped.Ciphertext, Context with { DataKeyId = Guid.NewGuid() });
        var otherPurpose = () => kms.Unwrap(wrapped.Ciphertext, Context with { Purpose = "blind-index" });

        otherId.Should().Throw<CryptographicException>();
        otherPurpose.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Another_kek_with_the_same_id_cannot_unwrap()
    {
        var wrapped = LocalKeyEncryptionService.CreateEphemeral("k").Wrap(RandomNumberGenerator.GetBytes(32), Context);

        var act = () => LocalKeyEncryptionService.CreateEphemeral("k").Unwrap(wrapped.Ciphertext, Context);

        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void A_version_that_does_not_exist_is_rejected()
    {
        var kms = LocalKeyEncryptionService.CreateEphemeral();
        var wrapped = kms.Wrap(RandomNumberGenerator.GetBytes(32), Context).Ciphertext;
        wrapped[3] = 9;

        var act = () => kms.Unwrap(wrapped, Context);

        act.Should().Throw<CryptographicException>().WithMessage("*version 9*");
    }

    [Fact]
    public void Key_file_survives_a_restart_including_rotations()
    {
        var path = Path.Combine(Path.GetTempPath(), $"fc-kek-{Guid.NewGuid():N}.json");
        try
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var first = LocalKeyEncryptionService.LoadOrCreate(path, "dev");
            var v1 = first.Wrap(key, Context);
            first.Rotate();

            var reloaded = LocalKeyEncryptionService.LoadOrCreate(path);

            reloaded.KeyId.Should().Be("dev");
            reloaded.CurrentVersion.Should().Be("2");
            reloaded.Unwrap(v1.Ciphertext, Context).Should().Equal(key);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Kek_versions_must_be_256_bit()
    {
        var act = () => new LocalKeyEncryptionService("k", [new byte[16]]);

        act.Should().Throw<ArgumentException>();
    }
}
