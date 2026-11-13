using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using FieldCrypto.Oci;
using Microsoft.Extensions.Time.Testing;

namespace FieldCrypto.UnitTests.Oci;

/// <summary>
/// The client signer against OCI's documented example: the "Request Signatures" page publishes a test RSA key pair and
/// the exact signing string for an example GET request (Fixtures/, copied verbatim; the key is Oracle's published
/// test-only key). The page gives no concrete signature value, so the signature is checked by verifying it with the
/// documented public key.
/// </summary>
public sealed class OciSignatureTests
{
    private const string DocUrl =
        "https://iaas.us-phoenix-1.oraclecloud.com/20160918/instances?availabilityDomain=Pjwf%3A%20PHX-AD-1&compartmentId=ocid1.compartment.oc1..aaaaaaaam3we6vgnherjq5q2idnccdflvjsnog7mlr6rtdb25gilchfeyjxa&displayName=TeamXInstances&volumeId=ocid1.volume.oc1.phx.abyhqljrgvttnlx73nmrwfaux7kcvzfs3s66izvxf2h4lgvyndsdsnoiwr5q";

    private static readonly DateTimeOffset DocDate = DateTimeOffset.Parse("2014-01-05T21:31:40Z", CultureInfo.InvariantCulture);

    private static string Fixture(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Oci", "Fixtures", name)).TrimEnd('\n', '\r');

    private static OciApiKey DocKey() => OciApiKey.FromPem("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", Fixture("oci-doc-test-private.pem"));

    private static RSA DocPublicKey()
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(Fixture("oci-doc-test-public.pem"));
        return rsa;
    }

    [Fact]
    public async Task Get_request_produces_the_documented_signing_string_and_a_signature_the_documented_key_verifies()
    {
        using var key = DocKey();
        var capture = new CapturingHandler();
        using var client = new HttpClient(new OciRequestSigningHandler(key, new FakeTimeProvider(DocDate)) { InnerHandler = capture });

        await client.GetAsync(new Uri(DocUrl), TestContext.Current.CancellationToken);

        var request = capture.Request!;
        OciSignature.TryParseAuthorization(capture.Header("authorization"), out var signature).Should().BeTrue();
        signature.Headers.Should().Equal("date", "(request-target)", "host");
        signature.KeyId.Should().Be(key.KeyId);
        var signingString = OciSignature.BuildSigningString("GET", request.RequestUri!.PathAndQuery, signature.Headers, name => name == "host" ? request.RequestUri.Host : capture.Header(name));
        // The documented date "Thu, 05 Jan 2014" names the wrong weekday (5 January 2014 was a Sunday); an RFC 1123
        // formatter cannot produce it, so only the weekday is adjusted. The documented string itself is matched exactly
        // in Signing_string_builder_reproduces_the_documented_example.
        signingString.Should().Be(Fixture("oci-doc-get-signing-string.txt").Replace("date: Thu,", "date: Sun,", StringComparison.Ordinal));
        using var publicKey = DocPublicKey();
        OciSignature.Verify(signingString, signature.Signature, publicKey).Should().BeTrue();
    }

    [Fact]
    public void Signing_string_builder_reproduces_the_documented_example()
    {
        var uri = new Uri(DocUrl);
        var headers = new Dictionary<string, string> { ["date"] = "Thu, 05 Jan 2014 21:31:40 GMT", ["host"] = uri.Host };

        var signingString = OciSignature.BuildSigningString("GET", uri.PathAndQuery, OciSignature.HeadersWithoutBody, n => headers.GetValueOrDefault(n));

        signingString.Should().Be(Fixture("oci-doc-get-signing-string.txt"));
        using var key = DocKey();
        using var publicKey = DocPublicKey();
        OciSignature.Verify(signingString, OciSignature.Sign(signingString, key.PrivateKey), publicKey).Should().BeTrue();
    }

    [Fact]
    public async Task Post_request_signs_body_headers_in_the_documented_order()
    {
        using var key = DocKey();
        var capture = new CapturingHandler();
        using var client = new HttpClient(new OciRequestSigningHandler(key, new FakeTimeProvider(DocDate)) { InnerHandler = capture });
        var body = "{\"keyId\":\"ocid1.key.oc1..k\",\"plaintext\":\"AAAA\"}"u8.ToArray();

        using var content = new ByteArrayContent(body);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        await client.PostAsync(new Uri("https://kms.example.test/20180608/encrypt"), content, TestContext.Current.CancellationToken);

        OciSignature.TryParseAuthorization(capture.Header("authorization"), out var signature).Should().BeTrue();
        signature.Headers.Should().Equal("date", "(request-target)", "host", "content-length", "content-type", "x-content-sha256");
        capture.Header("x-content-sha256").Should().Be(Convert.ToBase64String(SHA256.HashData(body)));
        capture.Body.Should().Equal(body);
    }

    [Fact]
    public void Synchronous_send_is_signed_too()
    {
        using var key = DocKey();
        var capture = new CapturingHandler();
        using var invoker = new HttpMessageInvoker(new OciRequestSigningHandler(key) { InnerHandler = capture });

        using var request = new HttpRequestMessage(HttpMethod.Post, "https://kms.example.test/20180608/decrypt") { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
        invoker.Send(request, TestContext.Current.CancellationToken);

        capture.Header("authorization").Should().StartWith("Signature version=\"1\"");
        capture.Header("x-content-sha256").Should().Be(OciSignature.ContentSha256("{}"u8));
    }

    [Fact]
    public void Fingerprint_is_md5_of_the_public_key_as_colon_hex()
    {
        using var publicKey = DocPublicKey();

        var fingerprint = OciApiKey.Fingerprint(publicKey);

        fingerprint.Should().MatchRegex("^([0-9a-f]{2}:){15}[0-9a-f]{2}$");
        fingerprint.Should().Be(OciApiKey.Fingerprint(DocKey().PrivateKey), "public and private halves name the same key");
    }

    [Theory]
    [InlineData("Basic abc")]
    [InlineData("Signature version=\"2\",headers=\"date\",keyId=\"k\",algorithm=\"rsa-sha256\",signature=\"s\"")]
    [InlineData("Signature version=\"1\",headers=\"date\",keyId=\"k\",algorithm=\"hmac-sha256\",signature=\"s\"")]
    [InlineData("Signature version=\"1\",headers=\"date\",keyId=\"k\",algorithm=\"rsa-sha256\"")]
    [InlineData("Signature version=\"1\" headers=\"date\"")]
    public void Malformed_or_unsupported_authorization_headers_are_rejected(string header) =>
        OciSignature.TryParseAuthorization(header, out _).Should().BeFalse();

    public sealed class Verifier
    {
        private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-13T10:00:00Z", CultureInfo.InvariantCulture);
        private readonly RSA _client = RSA.Create(2048);

        private (string Method, string Target, Dictionary<string, string> Headers, byte[] Body) SignedPost(byte[] body, DateTimeOffset? at = null)
        {
            var headers = new Dictionary<string, string>
            {
                ["date"] = (at ?? Now).ToString("r", CultureInfo.InvariantCulture),
                ["host"] = "kms.example.test",
                ["content-length"] = body.Length.ToString(CultureInfo.InvariantCulture),
                ["content-type"] = "application/json",
                ["x-content-sha256"] = OciSignature.ContentSha256(body),
            };
            var names = OciSignature.HeadersWithBody;
            var signature = OciSignature.Sign(OciSignature.BuildSigningString("POST", "/20180608/encrypt", names, n => headers.GetValueOrDefault(n)), _client);
            headers["authorization"] = OciSignature.AuthorizationHeader("client", names, signature);
            return ("POST", "/20180608/encrypt", headers, body);
        }

        private string? Verify((string Method, string Target, Dictionary<string, string> Headers, byte[] Body) r, string? target = null) =>
            new OciSignatureVerifier(id => id == "client" ? _client : null, new FakeTimeProvider(Now))
                .Verify(r.Method, target ?? r.Target, n => r.Headers.GetValueOrDefault(n), r.Body);

        [Fact]
        public void Accepts_a_correctly_signed_request() => Verify(SignedPost("{}"u8.ToArray())).Should().BeNull();

        [Fact]
        public void Rejects_a_changed_body()
        {
            var request = SignedPost("{\"a\":1}"u8.ToArray());

            Verify(request with { Body = "{\"a\":2}"u8.ToArray() }).Should().Contain("x-content-sha256");
        }

        [Fact]
        public void Rejects_a_changed_path() => Verify(SignedPost("{}"u8.ToArray()), "/20180608/decrypt").Should().Be("signature does not verify");

        [Fact]
        public void Rejects_a_stale_date() => Verify(SignedPost("{}"u8.ToArray(), Now.AddMinutes(-6))).Should().Contain("clock skew");

        [Fact]
        public void Rejects_an_unknown_key()
        {
            var request = SignedPost("{}"u8.ToArray());
            request.Headers["authorization"] = request.Headers["authorization"].Replace("keyId=\"client\"", "keyId=\"other\"", StringComparison.Ordinal);

            Verify(request).Should().Be("unknown keyId");
        }

        [Fact]
        public void Rejects_a_post_that_does_not_sign_its_body()
        {
            var request = SignedPost("{}"u8.ToArray());
            var names = OciSignature.HeadersWithoutBody;
            var signature = OciSignature.Sign(OciSignature.BuildSigningString("POST", request.Target, names, n => request.Headers.GetValueOrDefault(n)), _client);
            request.Headers["authorization"] = OciSignature.AuthorizationHeader("client", names, signature);

            Verify(request).Should().Contain("must be signed");
        }
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }

        public byte[]? Body { get; private set; }

        public string? Header(string name)
        {
            if (Request!.Headers.TryGetValues(name, out var values))
            {
                return string.Join(',', values);
            }

            return Request.Content is not null && Request.Content.Headers.TryGetValues(name, out var contentValues) ? string.Join(',', contentValues) : null;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            Body = request.Content is null ? null : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}
