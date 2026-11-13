using System.Security.Cryptography;
using FieldCrypto.DevKms;
using FieldCrypto.Oci;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;

namespace FieldCrypto.UnitTests.Oci;

/// <summary>The development KMS on a real Kestrel socket (loopback, random port), trusting one generated client key.</summary>
public sealed class DevKmsFixture : IAsyncLifetime
{
    public const string KeyOcid = "ocid1.key.oc1.dev.fieldcrypto.tests";

    private WebApplication? _app;

    public Uri Endpoint { get; private set; } = null!;

    public RSA ClientKey { get; } = RSA.Create(2048);

    public string ClientKeyId => $"{DevKmsApp.TenancyOcid}/{DevKmsApp.UserOcid}/{OciApiKey.Fingerprint(ClientKey)}";

    public async ValueTask InitializeAsync()
    {
        _app = DevKmsApp.Build(["--urls", "http://127.0.0.1:0"], o =>
        {
            o.KeyIds.Clear();
            o.KeyIds.Add(KeyOcid);
            o.TrustedKeys[ClientKeyId] = ClientKey.ExportSubjectPublicKeyInfoPem();
        });
        await _app.StartAsync();
        var address = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        Endpoint = new Uri(address);
    }

    public OciVaultKeyEncryptionService CreateService(RSA? signingKey = null, string keyOcid = KeyOcid)
    {
        var rsa = signingKey ?? ClientKey;
        var apiKey = new OciApiKey(DevKmsApp.TenancyOcid, DevKmsApp.UserOcid, OciApiKey.Fingerprint(rsa), rsa);
        return OciVaultKeyEncryptionService.Create(new OciVaultOptions { CryptoEndpoint = Endpoint, ManagementEndpoint = Endpoint, KeyId = keyOcid }, apiKey);
    }

    public async ValueTask DisposeAsync()
    {
        if (_app is not null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }

        ClientKey.Dispose();
    }
}
