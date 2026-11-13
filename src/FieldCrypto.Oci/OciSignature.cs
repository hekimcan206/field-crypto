using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace FieldCrypto.Oci;

/// <summary>
/// OCI API request signatures (draft-cavage HTTP signatures, version 1, rsa-sha256), as specified in
/// "Request Signatures" of the OCI documentation. Shared by the client handler and the development KMS's verifier,
/// and checked against the documented example signing string in the unit tests.
/// </summary>
public static class OciSignature
{
    public const string RequestTarget = "(request-target)";

    /// <summary>Minimum signed headers for GET and DELETE.</summary>
    public static IReadOnlyList<string> HeadersWithoutBody { get; } = ["date", RequestTarget, "host"];

    /// <summary>Minimum signed headers for POST and PUT.</summary>
    public static IReadOnlyList<string> HeadersWithBody { get; } =
        ["date", RequestTarget, "host", "content-length", "content-type", "x-content-sha256"];

    public static bool MethodHasBody(string method) =>
        string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase) || string.Equals(method, "PUT", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// One <c>name: value</c> line per signed header, in the listed order, joined by <c>\n</c> with no trailing newline.
    /// <c>(request-target)</c> is the lower-case method, a space, and the path and query exactly as sent.
    /// </summary>
    public static string BuildSigningString(string method, string pathAndQuery, IEnumerable<string> headerNames, Func<string, string?> headerValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentNullException.ThrowIfNull(headerNames);
        ArgumentNullException.ThrowIfNull(headerValue);
        var lines = headerNames.Select(name =>
        {
            var lower = name.ToLowerInvariant();
            if (lower == RequestTarget)
            {
                return $"{RequestTarget}: {method.ToLowerInvariant()} {pathAndQuery}";
            }

            var value = headerValue(lower) ?? throw new InvalidOperationException($"Header '{lower}' is listed for signing but missing.");
            return $"{lower}: {value}";
        });
        return string.Join('\n', lines);
    }

    public static string Sign(string signingString, RSA privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        var signature = privateKey.SignData(Encoding.UTF8.GetBytes(signingString), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }

    public static bool Verify(string signingString, string signatureBase64, RSA publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        Span<byte> signature = stackalloc byte[1024];
        if (!Convert.TryFromBase64String(signatureBase64, signature, out var length))
        {
            return false;
        }

        return publicKey.VerifyData(Encoding.UTF8.GetBytes(signingString), signature[..length], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public static string AuthorizationHeader(string keyId, IEnumerable<string> headerNames, string signatureBase64) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"Signature version=\"1\",headers=\"{string.Join(' ', headerNames)}\",keyId=\"{keyId}\",algorithm=\"rsa-sha256\",signature=\"{signatureBase64}\"");

    /// <summary>Base64 SHA-256 of the body, the value of <c>x-content-sha256</c> (also for an empty body).</summary>
    public static string ContentSha256(ReadOnlySpan<byte> body) => Convert.ToBase64String(SHA256.HashData(body));

    /// <summary>Parses <c>Signature k="v",...</c>. Returns false for anything that is not a version 1 rsa-sha256 signature.</summary>
    public static bool TryParseAuthorization(string? header, out ParsedSignature parsed)
    {
        parsed = default;
        const string scheme = "Signature ";
        if (header is null || !header.StartsWith(scheme, StringComparison.Ordinal))
        {
            return false;
        }

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
        var rest = header.AsSpan(scheme.Length);
        while (!rest.IsEmpty)
        {
            var equals = rest.IndexOf('=');
            if (equals <= 0 || rest.Length < equals + 2 || rest[equals + 1] != '"')
            {
                return false;
            }

            var name = rest[..equals].Trim().ToString();
            var valueStart = rest[(equals + 2)..];
            var close = valueStart.IndexOf('"');
            if (close < 0)
            {
                return false;
            }

            parameters[name] = valueStart[..close].ToString();
            rest = valueStart[(close + 1)..];
            if (!rest.IsEmpty)
            {
                if (rest[0] != ',')
                {
                    return false;
                }

                rest = rest[1..];
            }
        }

        if (!parameters.TryGetValue("version", out var version) || version != "1"
            || !parameters.TryGetValue("algorithm", out var algorithm) || algorithm != "rsa-sha256"
            || !parameters.TryGetValue("keyId", out var keyId) || keyId.Length == 0
            || !parameters.TryGetValue("headers", out var headers)
            || !parameters.TryGetValue("signature", out var signature))
        {
            return false;
        }

        parsed = new ParsedSignature(keyId, headers.Split(' ', StringSplitOptions.RemoveEmptyEntries), signature);
        return true;
    }
}

public readonly record struct ParsedSignature(string KeyId, IReadOnlyList<string> Headers, string Signature);
