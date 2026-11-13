using FieldCrypto.BlindIndexing;
using FieldCrypto.UnitTests.Support;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;

namespace FieldCrypto.UnitTests.Properties;

/// <summary>
/// The invariants the format promises: every value round-trips in its own context, any single changed bit is caught,
/// a context never authenticates as another, and rewrapping never changes what decrypts.
/// </summary>
public sealed class EnvelopeProperties : IDisposable
{
    private readonly TestRing _ring = new(new Keys.KeyRingOptions { MaxMessagesPerDataKey = 64 });

    public void Dispose() => _ring.Dispose();

    private static Arbitrary<EncryptionContext> Contexts() =>
        (from table in Gen.Elements("patients", "staff", "lab_results", "ş")
         from column in Gen.Elements("national_id", "email", "phone", "note")
         from row in Gen.OneOf(Gen.Constant<string?>(null), Gen.Choose(1, 1_000_000).Select(i => (string?)i.ToString(System.Globalization.CultureInfo.InvariantCulture)))
         select new EncryptionContext(table, column, row)).ToArbitrary();

    [Property(MaxTest = 500)]
    public Property Every_value_round_trips_in_its_context() =>
        Prop.ForAll(ArbMap.Default.ArbFor<NonNull<string>>(), Contexts(), (text, context) =>
            _ring.Encryptor.Decrypt(_ring.Encryptor.Encrypt(text.Get, context), context) == text.Get);

    [Property(MaxTest = 300)]
    public Property Flipping_any_single_bit_is_detected() =>
        Prop.ForAll(ArbMap.Default.ArbFor<NonNull<string>>(), ArbMap.Default.ArbFor<PositiveInt>(), (text, position) =>
        {
            var context = new EncryptionContext("patients", "note", "7");
            var ciphertext = _ring.Encryptor.Encrypt(text.Get, context);
            var bit = position.Get % (ciphertext.Length * 8);
            ciphertext[bit / 8] ^= (byte)(1 << (bit % 8));
            try
            {
                _ring.Encryptor.Decrypt(ciphertext, context);
                return false;
            }
            catch (FieldDecryptionException)
            {
                return true;
            }
        });

    [Property(MaxTest = 300)]
    public Property A_ciphertext_never_authenticates_under_a_different_context() =>
        Prop.ForAll(Contexts(), Contexts(), (written, read) =>
        {
            var ciphertext = _ring.Encryptor.Encrypt("10000000146", written);
            try
            {
                return _ring.Encryptor.Decrypt(ciphertext, read) == "10000000146" && written == read;
            }
            catch (FieldDecryptionException)
            {
                return written != read;
            }
        });

    [Property(MaxTest = 300)]
    public Property Context_encoding_is_injective() =>
        Prop.ForAll(Contexts(), Contexts(), (a, b) =>
            a.Encode().AsSpan().SequenceEqual(b.Encode()) == (a == b));

    [Property(MaxTest = 300)]
    public Property Blind_index_stays_within_its_bit_range() =>
        Prop.ForAll(ArbMap.Default.ArbFor<NonNull<string>>(), Gen.Choose(1, 32).ToArbitrary(), (text, bits) =>
        {
            var value = _ring.Indexer.Compute(text.Get, new BlindIndexDefinition("patients", "note", bits));
            return value >= 0 && value < (1L << bits);
        });

    [Property(MaxTest = 200)]
    public Property Turkish_case_fold_is_idempotent() =>
        Prop.ForAll(ArbMap.Default.ArbFor<NonNull<string>>(), text =>
        {
            var once = TextNormalizers.TurkishCaseFold(text.Get);
            return TextNormalizers.TurkishCaseFold(once) == once;
        });

    [Property(MaxTest = 20)]
    public Property Rewrapping_after_rotation_never_changes_a_plaintext() =>
        Prop.ForAll(ArbMap.Default.ArbFor<NonNull<string>[]>(), texts =>
        {
            var context = new EncryptionContext("patients", "note");
            var sealedValues = texts.Select(t => (t.Get, Cipher: _ring.Encryptor.Encrypt(t.Get, context))).ToList();
            _ring.Kek.Rotate();
            _ring.Ring.RewrapAsync().GetAwaiter().GetResult();
            using var restarted = _ring.Restart();
            return sealedValues.All(v => restarted.Encryptor.Decrypt(v.Cipher, context) == v.Get);
        });
}
