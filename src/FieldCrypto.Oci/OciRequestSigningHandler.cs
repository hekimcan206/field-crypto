using System.Globalization;
using System.Net.Http.Headers;

namespace FieldCrypto.Oci;

/// <summary>
/// Signs every outgoing request with an OCI API key. Both <see cref="Send"/> and <see cref="SendAsync"/> are
/// implemented, so the synchronous KMS path (EF Core value converters) stays synchronous end to end.
/// </summary>
public sealed class OciRequestSigningHandler(OciApiKey apiKey, TimeProvider? timeProvider = null) : DelegatingHandler
{
    private readonly OciApiKey _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        byte[] body = [];
        if (request.Content is not null)
        {
            using var stream = request.Content.ReadAsStream(cancellationToken);
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            body = buffer.ToArray();
        }

        SignRequest(request, body);
        return base.Send(request, cancellationToken);
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        SignRequest(request, body);
        return await base.SendAsync(request, cancellationToken);
    }

    private void SignRequest(HttpRequestMessage request, byte[] body)
    {
        var uri = request.RequestUri ?? throw new InvalidOperationException("Request has no URI.");
        var method = request.Method.Method;
        var date = _time.GetUtcNow().ToString("r", CultureInfo.InvariantCulture);
        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["date"] = date,
            ["host"] = uri.IsDefaultPort ? uri.Host : uri.Authority,
        };
        request.Headers.TryAddWithoutValidation("date", date);

        var headerNames = OciSignature.HeadersWithoutBody;
        if (OciSignature.MethodHasBody(method))
        {
            headerNames = OciSignature.HeadersWithBody;
            // A body is replaced by an equivalent byte array so the signed length and hash are exactly what is sent.
            var contentType = request.Content?.Headers.ContentType ?? new MediaTypeHeaderValue("application/json");
            var content = new ByteArrayContent(body);
            content.Headers.ContentType = contentType;
            content.Headers.ContentLength = body.Length;
            request.Content = content;
            values["content-length"] = body.Length.ToString(CultureInfo.InvariantCulture);
            values["content-type"] = contentType.ToString();
            values["x-content-sha256"] = OciSignature.ContentSha256(body);
            request.Headers.TryAddWithoutValidation("x-content-sha256", values["x-content-sha256"]);
        }

        var signingString = OciSignature.BuildSigningString(method, uri.PathAndQuery, headerNames, name => values.GetValueOrDefault(name));
        var signature = OciSignature.Sign(signingString, _apiKey.PrivateKey);
        request.Headers.TryAddWithoutValidation("authorization", OciSignature.AuthorizationHeader(_apiKey.KeyId, headerNames, signature));
    }
}
