using System.Net;
using System.Security.Cryptography;
using FieldCrypto.Keys;
using FieldCrypto.Kms;
using FieldCrypto.Oci;

namespace FieldCrypto.UnitTests.Oci;

/// <summary>
/// The OCI Vault adapter end to end over HTTP against the development KMS: signed requests, wrap/unwrap in both the
/// synchronous and asynchronous paths, key versions and rotation, and the error mapping the key ring relies on.
/// </summary>
public sealed class OciVaultAdapterTests(DevKmsFixture kms) : IClassFixture<DevKmsFixture>
{
    private static readonly KeyWrapContext Context = new(Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8057"), "data");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Wraps_and_unwraps_through_both_paths()
    {
        var service = kms.CreateService();
        var key = RandomNumberGenerator.GetBytes(32);

        var asyncWrapped = await service.WrapAsync(key, Context, Ct);
        var syncWrapped = service.Wrap(key, Context);

        (await service.UnwrapAsync(syncWrapped.Ciphertext, Context, Ct)).Should().Equal(key);
        service.Unwrap(asyncWrapped.Ciphertext, Context).Should().Equal(key);
        asyncWrapped.KeyVersion.Should().StartWith("ocid1.keyversion.oc1.dev.fieldcrypto.tests.");
    }

    [Fact]
    public async Task Rotation_creates_a_version_new_wraps_use_and_old_wraps_still_unwrap()
    {
        var service = kms.CreateService();
        var key = RandomNumberGenerator.GetBytes(32);
        var before = await service.WrapAsync(key, Context, Ct);

        var created = await service.CreateKeyVersionAsync(Ct);
        var after = await service.WrapAsync(key, Context, Ct);

        (await service.GetCurrentKeyVersionAsync(Ct)).Should().Be(created);
        after.KeyVersion.Should().Be(created).And.NotBe(before.KeyVersion);
        (await service.UnwrapAsync(before.Ciphertext, Context, Ct)).Should().Equal(key);
    }

    [Fact]
    public async Task Associated_data_mismatch_is_a_cryptographic_failure()
    {
        var service = kms.CreateService();
        var wrapped = await service.WrapAsync(RandomNumberGenerator.GetBytes(32), Context, Ct);

        var act = () => service.UnwrapAsync(wrapped.Ciphertext, Context with { DataKeyId = Guid.NewGuid() }, Ct);

        (await act.Should().ThrowAsync<CryptographicException>()).WithMessage("*400 InvalidParameter*");
    }

    [Fact]
    public async Task An_untrusted_signing_key_is_refused_with_401()
    {
        using var stranger = RSA.Create(2048);
        var service = kms.CreateService(stranger);

        var act = () => service.WrapAsync(new byte[32], Context, Ct);

        (await act.Should().ThrowAsync<OciVaultException>()).Which.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task An_unknown_key_ocid_is_404()
    {
        var service = kms.CreateService(keyOcid: "ocid1.key.oc1.dev.missing");

        var act = () => service.GetCurrentKeyVersionAsync(Ct);

        (await act.Should().ThrowAsync<OciVaultException>()).Which.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Unsigned_requests_are_rejected()
    {
        using var http = new HttpClient();

        using var response = await http.PostAsync(new Uri(kms.Endpoint, "/20180608/encrypt"), new StringContent("{}"), Ct);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_key_ring_on_oci_vault_rotates_by_rewrapping_data_keys_only()
    {
        var service = kms.CreateService();
        var store = new InMemoryDataKeyStore();
        var context = new EncryptionContext("patients", "national_id");
        byte[] ciphertext;
        using (var ring = new KeyRing(service, store, new KeyRingOptions { MaxMessagesPerDataKey = 50 }))
        {
            var encryptor = new FieldEncryptor(ring);
            ciphertext = encryptor.Encrypt("10000000146", context);
            for (var i = 0; i < 199; i++)
            {
                encryptor.Encrypt("x", context);
            }

            ring.Statistics.KmsWraps.Should().Be(4, "200 encryptions at 50 per data key");
            await service.CreateKeyVersionAsync(Ct);
            var result = await ring.RewrapAsync(Ct);
            result.Rewrapped.Should().Be(4);
        }

        using var restarted = new KeyRing(service, store);
        new FieldEncryptor(restarted).Decrypt(ciphertext, context).Should().Be("10000000146");
        var current = await service.GetCurrentKeyVersionAsync(Ct);
        (await store.ListAsync(Ct)).Should().OnlyContain(r => r.KekVersion == current);
    }
}
