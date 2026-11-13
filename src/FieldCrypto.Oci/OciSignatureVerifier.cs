using System.Globalization;
using System.Security.Cryptography;

namespace FieldCrypto.Oci;

/// <summary>
/// Server-side check of an OCI-signed request, used by the development KMS so the client signer is exercised against
/// the same rules OCI enforces: required headers signed, body hash and length matching, clock skew bounded.
/// </summary>
public sealed class OciSignatureVerifier(Func<string, RSA?> publicKeyForKeyId, TimeProvider? timeProvider = null)
{
    private readonly Func<string, RSA?> _publicKeyForKeyId = publicKeyForKeyId ?? throw new ArgumentNullException(nameof(publicKeyForKeyId));
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public TimeSpan MaxClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <returns>Null when the request is authentic, otherwise the reason it is not.</returns>
    public string? Verify(string method, string pathAndQuery, Func<string, string?> header, ReadOnlySpan<byte> body)
    {
        ArgumentNullException.ThrowIfNull(header);
        if (!OciSignature.TryParseAuthorization(header("authorization"), out var signature))
        {
            return "missing or malformed Authorization signature";
        }

        var signed = new HashSet<string>(signature.Headers, StringComparer.Ordinal);
        var required = OciSignature.MethodHasBody(method) ? OciSignature.HeadersWithBody : OciSignature.HeadersWithoutBody;
        foreach (var name in required)
        {
            // OCI accepts x-date in place of date.
            if (!signed.Contains(name) && !(name == "date" && signed.Contains("x-date")))
            {
                return $"header '{name}' must be signed";
            }
        }

        var dateValue = signed.Contains("x-date") ? header("x-date") : header("date");
        if (!DateTimeOffset.TryParseExact(dateValue, "r", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var date)
            || (_time.GetUtcNow() - date).Duration() > MaxClockSkew)
        {
            return "date missing or outside the allowed clock skew";
        }

        if (signed.Contains("x-content-sha256") && header("x-content-sha256") != OciSignature.ContentSha256(body))
        {
            return "x-content-sha256 does not match the body";
        }

        if (signed.Contains("content-length") && header("content-length") != body.Length.ToString(CultureInfo.InvariantCulture))
        {
            return "content-length does not match the body";
        }

        var key = _publicKeyForKeyId(signature.KeyId);
        if (key is null)
        {
            return "unknown keyId";
        }

        string signingString;
        try
        {
            signingString = OciSignature.BuildSigningString(method, pathAndQuery, signature.Headers, header);
        }
        catch (InvalidOperationException ex)
        {
            return ex.Message;
        }

        return OciSignature.Verify(signingString, signature.Signature, key) ? null : "signature does not verify";
    }
}
