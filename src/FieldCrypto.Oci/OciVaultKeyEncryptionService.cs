using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FieldCrypto.Kms;

namespace FieldCrypto.Oci;

public sealed class OciVaultOptions
{
    /// <summary>The vault's crypto endpoint (data plane), e.g. https://xxxx-crypto.kms.eu-frankfurt-1.oraclecloud.com.</summary>
    public required Uri CryptoEndpoint { get; init; }

    /// <summary>The vault's management endpoint, used to read the current key version and to rotate.</summary>
    public required Uri ManagementEndpoint { get; init; }

    /// <summary>OCID of the AES master encryption key.</summary>
    public required string KeyId { get; init; }
}

/// <summary>
/// Wraps data keys with an OCI Vault master encryption key through the KMS crypto API (<c>POST /20180608/encrypt</c>
/// and <c>/decrypt</c>); the key never leaves the vault. The HttpClient must carry an
/// <see cref="OciRequestSigningHandler"/> (see <see cref="Create"/>).
/// </summary>
/// <remarks>
/// Written against the request and response shapes of the OCI SDK models (EncryptDataDetails, EncryptedData,
/// DecryptDataDetails, DecryptedData, Key, KeyVersion) and tested against the repository's development KMS, which
/// implements the same subset. It has not been run against a live OCI tenancy; see the README's limitations.
/// </remarks>
public sealed class OciVaultKeyEncryptionService : IKeyEncryptionService
{
    private const string ApiVersion = "/20180608";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _http;
    private readonly OciVaultOptions _options;

    public OciVaultKeyEncryptionService(HttpClient httpClient, OciVaultOptions options)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        ArgumentException.ThrowIfNullOrWhiteSpace(options.KeyId);
    }

    public string KeyId => _options.KeyId;

    /// <summary>A service with its own signed HttpClient. The client lives as long as the service (one per process).</summary>
    public static OciVaultKeyEncryptionService Create(OciVaultOptions options, OciApiKey apiKey, TimeSpan? timeout = null)
    {
        var handler = new OciRequestSigningHandler(apiKey) { InnerHandler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) } };
        return new OciVaultKeyEncryptionService(new HttpClient(handler) { Timeout = timeout ?? TimeSpan.FromSeconds(10) }, options);
    }

    public async Task<string> GetCurrentKeyVersionAsync(CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Management($"/keys/{Uri.EscapeDataString(KeyId)}"));
        using var response = await _http.SendAsync(request, cancellationToken);
        var key = await ReadAsync<KeyResponse>(response, cancellationToken);
        return key.CurrentKeyVersion;
    }

    /// <summary>Creates a new key version (OCI "rotate key"). New wraps use it; old versions keep decrypting.</summary>
    public async Task<string> CreateKeyVersionAsync(CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, Management($"/keys/{Uri.EscapeDataString(KeyId)}/keyVersions"))
        {
            Content = JsonContent.Create(new { }, options: Json),
        };
        using var response = await _http.SendAsync(request, cancellationToken);
        var version = await ReadAsync<KeyVersionResponse>(response, cancellationToken);
        return version.Id;
    }

    public async Task<WrappedDataKey> WrapAsync(ReadOnlyMemory<byte> plaintextKey, KeyWrapContext context, CancellationToken cancellationToken = default)
    {
        using var request = EncryptRequest(plaintextKey.Span, context);
        using var response = await _http.SendAsync(request, cancellationToken);
        return ToWrapped(await ReadAsync<EncryptResponse>(response, cancellationToken));
    }

    public WrappedDataKey Wrap(ReadOnlySpan<byte> plaintextKey, KeyWrapContext context)
    {
        using var request = EncryptRequest(plaintextKey, context);
        using var response = _http.Send(request);
        return ToWrapped(Read<EncryptResponse>(response));
    }

    public async Task<byte[]> UnwrapAsync(ReadOnlyMemory<byte> wrappedKey, KeyWrapContext context, CancellationToken cancellationToken = default)
    {
        using var request = DecryptRequest(wrappedKey.Span, context);
        using var response = await _http.SendAsync(request, cancellationToken);
        return FromDecrypted(await ReadAsync<DecryptResponse>(response, cancellationToken));
    }

    public byte[] Unwrap(ReadOnlySpan<byte> wrappedKey, KeyWrapContext context)
    {
        using var request = DecryptRequest(wrappedKey, context);
        using var response = _http.Send(request);
        return FromDecrypted(Read<DecryptResponse>(response));
    }

    private HttpRequestMessage EncryptRequest(ReadOnlySpan<byte> plaintextKey, KeyWrapContext context) =>
        Post("/encrypt", new EncryptRequestBody(KeyId, Convert.ToBase64String(plaintextKey), context.ToAssociatedData()));

    // The OCI ciphertext is an opaque base64 string that names its own key version; it is stored as its UTF-8 bytes,
    // never decoded or re-encoded, so nothing depends on how OCI pads or formats it.
    private HttpRequestMessage DecryptRequest(ReadOnlySpan<byte> wrappedKey, KeyWrapContext context) =>
        Post("/decrypt", new DecryptRequestBody(KeyId, Encoding.UTF8.GetString(wrappedKey), context.ToAssociatedData()));

    private HttpRequestMessage Post(string path, object body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_options.CryptoEndpoint, ApiVersion + path))
        {
            Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(body, body.GetType(), Json)),
        };
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation("opc-request-id", Guid.NewGuid().ToString("N"));
        return request;
    }

    private Uri Management(string path) => new(_options.ManagementEndpoint, ApiVersion + path);

    private static WrappedDataKey ToWrapped(EncryptResponse response) =>
        new(response.KeyVersionId, Encoding.UTF8.GetBytes(response.Ciphertext));

    private static byte[] FromDecrypted(DecryptResponse response) => Convert.FromBase64String(response.Plaintext);

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw Failure(response, await response.Content.ReadAsStringAsync(cancellationToken));
        }

        return await response.Content.ReadFromJsonAsync<T>(Json, cancellationToken)
            ?? throw new OciVaultException(response.StatusCode, "empty response body", RequestId(response));
    }

    private static T Read<T>(HttpResponseMessage response)
    {
        using var stream = response.Content.ReadAsStream();
        if (!response.IsSuccessStatusCode)
        {
            using var reader = new StreamReader(stream);
            throw Failure(response, reader.ReadToEnd());
        }

        return JsonSerializer.Deserialize<T>(stream, Json)
            ?? throw new OciVaultException(response.StatusCode, "empty response body", RequestId(response));
    }

    /// <summary>
    /// 400 from decrypt means the ciphertext or its associated data was rejected: a cryptographic failure, which the
    /// key ring reports as an unwrap failure. Everything else (auth, throttling, outage) is an infrastructure error.
    /// </summary>
    private static Exception Failure(HttpResponseMessage response, string body)
    {
        var error = TryParseError(body);
        var message = $"OCI Vault returned {(int)response.StatusCode} {error?.Code}: {error?.Message}";
        return response.StatusCode == HttpStatusCode.BadRequest
            ? new CryptographicException(message)
            : new OciVaultException(response.StatusCode, message, RequestId(response));
    }

    private static ErrorResponse? TryParseError(string body)
    {
        try
        {
            return JsonSerializer.Deserialize<ErrorResponse>(body, Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? RequestId(HttpResponseMessage response) =>
        response.Headers.TryGetValues("opc-request-id", out var values) ? values.FirstOrDefault() : null;

    private sealed record EncryptRequestBody(string KeyId, string Plaintext, IReadOnlyDictionary<string, string> AssociatedData);

    private sealed record DecryptRequestBody(string KeyId, string Ciphertext, IReadOnlyDictionary<string, string> AssociatedData);

    private sealed record EncryptResponse(string Ciphertext, string KeyId, string KeyVersionId);

    private sealed record DecryptResponse(string Plaintext);

    private sealed record KeyResponse(string Id, string CurrentKeyVersion);

    private sealed record KeyVersionResponse(string Id, string KeyId);

    private sealed record ErrorResponse(string? Code, string? Message);
}

/// <summary>An OCI Vault call failed for a reason other than a rejected ciphertext.</summary>
public sealed class OciVaultException : Exception
{
    public OciVaultException()
    {
    }

    public OciVaultException(string message)
        : base(message)
    {
    }

    public OciVaultException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public OciVaultException(HttpStatusCode statusCode, string message, string? requestId)
        : base(requestId is null ? message : $"{message} (opc-request-id {requestId})")
    {
        StatusCode = statusCode;
        RequestId = requestId;
    }

    public HttpStatusCode StatusCode { get; }

    public string? RequestId { get; }
}
