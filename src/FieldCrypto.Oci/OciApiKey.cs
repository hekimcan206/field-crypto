using System.Security.Cryptography;

namespace FieldCrypto.Oci;

/// <summary>
/// An OCI API signing key: the RSA private key plus the identifiers OCI uses to find its public half.
/// The signature <c>keyId</c> is <c>tenancy OCID / user OCID / key fingerprint</c>.
/// </summary>
public sealed class OciApiKey : IDisposable
{
    public OciApiKey(string tenancyOcid, string userOcid, string fingerprint, RSA privateKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenancyOcid);
        ArgumentException.ThrowIfNullOrWhiteSpace(userOcid);
        ArgumentException.ThrowIfNullOrWhiteSpace(fingerprint);
        PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        KeyId = $"{tenancyOcid}/{userOcid}/{fingerprint}";
    }

    public string KeyId { get; }

    public RSA PrivateKey { get; }

    /// <summary>Loads a PEM private key (PKCS#1 or PKCS#8) and computes its OCI fingerprint.</summary>
    public static OciApiKey FromPem(string tenancyOcid, string userOcid, string privateKeyPem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        return new OciApiKey(tenancyOcid, userOcid, Fingerprint(rsa), rsa);
    }

    /// <summary>
    /// OCI key fingerprint: MD5 of the DER-encoded SubjectPublicKeyInfo, as colon-separated lower-case hex. MD5 here is
    /// an identifier OCI defines, not a security control.
    /// </summary>
    public static string Fingerprint(RSA key)
    {
        ArgumentNullException.ThrowIfNull(key);
#pragma warning disable CA5351 // OCI defines the API key fingerprint as MD5; it names the key, it does not protect anything.
        var hash = MD5.HashData(key.ExportSubjectPublicKeyInfo());
#pragma warning restore CA5351
        return string.Join(':', hash.Select(b => b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture)));
    }

    public void Dispose() => PrivateKey.Dispose();
}
