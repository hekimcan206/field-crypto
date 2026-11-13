using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text.Json;
using FieldCrypto.Oci;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

namespace FieldCrypto.DevKms;

/// <summary>
/// The OCI Vault API subset FieldCrypto uses: <c>POST /20180608/encrypt</c>, <c>POST /20180608/decrypt</c>,
/// <c>GET /20180608/keys/{keyId}</c> and <c>POST /20180608/keys/{keyId}/keyVersions</c>, on one listener (OCI splits
/// them over a crypto and a management endpoint). Every API call must carry a valid OCI request signature.
/// </summary>
public static class DevKmsApp
{
    public const string TenancyOcid = "ocid1.tenancy.oc1..devtenancy";
    public const string UserOcid = "ocid1.user.oc1..devuser";
    public const string ClientKeyFile = "client_key.pem";
    public const string ClientKeyIdFile = "client_key_id.txt";

    private static readonly Meter Meter = new("FieldCrypto.DevKms");
    private static readonly Counter<long> Requests = Meter.CreateCounter<long>("devkms.requests");

    public static WebApplication Build(string[] args, Action<DevKmsOptions>? configure = null)
    {
        var builder = WebApplication.CreateSlimBuilder(args);
        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole(o => o.TimestampFormat = "O");
        builder.Services.AddOptions<DevKmsOptions>().Bind(builder.Configuration.GetSection(DevKmsOptions.Section));
        if (configure is not null)
        {
            builder.Services.PostConfigure(configure);
        }

        builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase);
        builder.Services.AddSingleton(sp => new MasterKeyStore(sp.GetRequiredService<IOptions<DevKmsOptions>>().Value.KeyIds, sp.GetRequiredService<IOptions<DevKmsOptions>>().Value.StatePath));
        builder.Services.AddSingleton(sp => TrustedKeys.Load(sp.GetRequiredService<IOptions<DevKmsOptions>>().Value, sp.GetRequiredService<ILoggerFactory>().CreateLogger("DevKms")));
        builder.Services.AddSingleton(sp => new OciSignatureVerifier(
            sp.GetRequiredService<TrustedKeys>().Find,
            TimeProvider.System)
        { MaxClockSkew = sp.GetRequiredService<IOptions<DevKmsOptions>>().Value.MaxClockSkew });

        var app = builder.Build();
        app.Services.GetRequiredService<MasterKeyStore>();
        app.Services.GetRequiredService<TrustedKeys>();

        // Middleware, not an endpoint filter: filters run after model binding has consumed the body, and the body hash
        // must be checked against the exact bytes received.
        app.UseWhen(c => c.Request.Path.StartsWithSegments("/20180608"), branch => branch.Use(VerifySignature));

        app.MapGet("/healthz", () => Results.Text("ok"));

        var api = app.MapGroup("/20180608");
        api.MapPost("/encrypt", Encrypt);
        api.MapPost("/decrypt", Decrypt);
        api.MapGet("/keys/{keyId}", GetKey);
        api.MapPost("/keys/{keyId}/keyVersions", CreateKeyVersion);
        return app;
    }

    private static async Task VerifySignature(HttpContext http, RequestDelegate next)
    {
        http.Request.EnableBuffering();
        using var buffer = new MemoryStream();
        await http.Request.Body.CopyToAsync(buffer, http.RequestAborted);
        http.Request.Body.Position = 0;

        var rawTarget = http.Features.Get<IHttpRequestFeature>()?.RawTarget ?? (http.Request.Path + http.Request.QueryString);
        var verifier = http.RequestServices.GetRequiredService<OciSignatureVerifier>();
        var failure = verifier.Verify(http.Request.Method, rawTarget, name => name switch
        {
            "host" => http.Request.Host.Value,
            "content-length" => http.Request.ContentLength?.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "content-type" => http.Request.ContentType,
            _ => http.Request.Headers.TryGetValue(name, out var v) ? v.ToString() : null,
        }, buffer.ToArray());

        Requests.Add(1, new KeyValuePair<string, object?>("authenticated", failure is null));
        if (failure is not null)
        {
            DevKmsLog.Rejected(http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("DevKms"), http.Request.Method, rawTarget, failure);
            await Error(StatusCodes.Status401Unauthorized, "NotAuthenticated", failure).ExecuteAsync(http);
            return;
        }

        var latency = http.RequestServices.GetRequiredService<IOptions<DevKmsOptions>>().Value.SimulatedLatency;
        if (latency > TimeSpan.Zero)
        {
            await Task.Delay(latency, http.RequestAborted);
        }

        await next(http);
    }

    private static IResult Encrypt(EncryptBody body, MasterKeyStore keys)
    {
        byte[] plaintext;
        try
        {
            plaintext = Convert.FromBase64String(body.Plaintext ?? string.Empty);
        }
        catch (FormatException)
        {
            return Error(StatusCodes.Status400BadRequest, "InvalidParameter", "plaintext must be base64");
        }

        var result = keys.Encrypt(body.KeyId ?? string.Empty, plaintext, body.AssociatedData);
        return result is null
            ? Error(StatusCodes.Status404NotFound, "NotAuthorizedOrNotFound", "key not found")
            : Results.Ok(new { ciphertext = result.Value.Ciphertext, keyId = body.KeyId, keyVersionId = result.Value.VersionId, encryptionAlgorithm = "AES_256_GCM" });
    }

    private static IResult Decrypt(DecryptBody body, MasterKeyStore keys)
    {
        try
        {
            var result = keys.Decrypt(body.KeyId ?? string.Empty, body.Ciphertext ?? string.Empty, body.AssociatedData);
            return result is null
                ? Error(StatusCodes.Status404NotFound, "NotAuthorizedOrNotFound", "key not found")
                : Results.Ok(new { plaintext = Convert.ToBase64String(result.Value.Plaintext), keyId = body.KeyId, keyVersionId = result.Value.VersionId, encryptionAlgorithm = "AES_256_GCM" });
        }
        catch (CryptographicException)
        {
            // Same answer for every rejection: a decrypt oracle should not say which check failed.
            return Error(StatusCodes.Status400BadRequest, "InvalidParameter", "ciphertext or associated data rejected");
        }
    }

    private static IResult GetKey(string keyId, MasterKeyStore keys)
    {
        var current = keys.CurrentVersion(keyId);
        return current is null
            ? Error(StatusCodes.Status404NotFound, "NotAuthorizedOrNotFound", "key not found")
            : Results.Ok(new { id = keyId, currentKeyVersion = current, lifecycleState = "ENABLED", keyShape = new { algorithm = "AES", length = 32 } });
    }

    private static IResult CreateKeyVersion(string keyId, MasterKeyStore keys)
    {
        var version = keys.AddVersion(keyId);
        return version is null
            ? Error(StatusCodes.Status404NotFound, "NotAuthorizedOrNotFound", "key not found")
            : Results.Ok(new { id = version, keyId, lifecycleState = "ENABLED" });
    }

    private static IResult Error(int status, string code, string message) =>
        Results.Json(new { code, message }, statusCode: status);

    private sealed record EncryptBody(string? KeyId, string? Plaintext, Dictionary<string, string>? AssociatedData);

    private sealed record DecryptBody(string? KeyId, string? Ciphertext, Dictionary<string, string>? AssociatedData);
}

/// <summary>Public keys allowed to sign requests: configured ones plus the generated client key.</summary>
internal sealed class TrustedKeys
{
    private readonly Dictionary<string, RSA> _keys = new(StringComparer.Ordinal);

    public RSA? Find(string keyId) => _keys.GetValueOrDefault(keyId);

    public static TrustedKeys Load(DevKmsOptions options, ILogger logger)
    {
        var trusted = new TrustedKeys();
        foreach (var (keyId, pem) in options.TrustedKeys)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            trusted._keys[keyId] = rsa;
        }

        if (options.ClientKeyDirectory is { } directory)
        {
            Directory.CreateDirectory(directory);
            var keyPath = Path.Combine(directory, DevKmsApp.ClientKeyFile);
            var rsa = RSA.Create(2048);
            if (File.Exists(keyPath))
            {
                rsa.ImportFromPem(File.ReadAllText(keyPath));
            }
            else
            {
                File.WriteAllText(keyPath, rsa.ExportPkcs8PrivateKeyPem());
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
            }

            var keyId = $"{DevKmsApp.TenancyOcid}/{DevKmsApp.UserOcid}/{OciApiKey.Fingerprint(rsa)}";
            File.WriteAllText(Path.Combine(directory, DevKmsApp.ClientKeyIdFile), keyId);
            trusted._keys[keyId] = rsa;
            DevKmsLog.ClientKeyTrusted(logger, keyId);
        }

        return trusted;
    }
}

internal static partial class DevKmsLog
{
    [LoggerMessage(Level = LogLevel.Information, Message = "Development client key trusted as {KeyId}")]
    public static partial void ClientKeyTrusted(ILogger logger, string keyId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Rejected {Method} {Target}: {Reason}")]
    public static partial void Rejected(ILogger logger, string method, string target, string reason);
}
