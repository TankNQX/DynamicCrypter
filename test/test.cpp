// ============================================================================
//  DynamicCrypter test driver
// ----------------------------------------------------------------------------
//  Two layers of verification:
//
//   1. Compile-time proofs. A full cycle (plain -> cipher -> plain, then
//      plain -> cipher again) has to hold as a constant expression for every
//      value of every dimension, for the classic presets, for a spread of
//      random dimension combinations and for every character type, so a broken
//      dimension cannot even be built.
//
//   2. Run-time checks. The object macro is checked against its documented
//      lifetime and state machine - it decodes on read, encrypt() hides the
//      text again, clear() ends it - decoding is shown to leave the site's own
//      storage untouched, and every preset is exercised end to end through the
//      core engine.
//
//  The compile-time proofs are deliberately split into many small evaluations
//  (one static_assert per flavour) instead of a few recursive ones, because
//  MSVC budgets constant evaluation per expression (/constexpr:steps, 100k by
//  default) - a single grand sweep through the whole product space would
//  exceed it.
//
//  Exits with a non-zero status if any check fails.
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iostream>

#include "DynamicCrypter.hpp"

namespace {

int g_failures = 0;

void report(const char* what, bool ok) {
    std::printf("  [%s] %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) {
        ++g_failures;
    }
}

// Takes plain pointers so that string literals and CRYPT_STR*() results can
// both be passed; a single overload avoids an ambiguous template match between
// "const T*" and "const T(&)[N]".
template <typename CharType>
bool same_text(const CharType* left, const CharType* right) {
    for (size_t i = 0;; ++i) {
        if (left[i] != right[i]) {
            return false;
        }
        if (right[i] == static_cast<CharType>(0)) {
            return true;
        }
    }
}

// ---------------------------------------------------------------------------
//  Shorthands for the dimension names
// ---------------------------------------------------------------------------
using DynamicCrypter::Combiner;
using DynamicCrypter::Keygen;
using DynamicCrypter::Mode;
using DynamicCrypter::Order;

template <Keygen K, Combiner C, Mode M, Order O>
using F = DynamicCrypter::Flavour<K, C, M, O>;

// ---------------------------------------------------------------------------
//  Test data
// ---------------------------------------------------------------------------
constexpr char kTiny[] = "DynCrypt";
constexpr char kShort[] = "DynamicCrypter polymorphic 0123456789";
constexpr char kLong[] =
    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*(){}[]";
constexpr wchar_t kWide[] = L"Wide polymorphic round trip 0123456789";
constexpr char16_t kU16[] = u"UTF-16 polymorphic round trip 0123456789";
constexpr char32_t kU32[] = U"UTF-32 polymorphic round trip 0123456789";

// ---------------------------------------------------------------------------
//  Namespace-scope call sites
// ---------------------------------------------------------------------------
//  CRYPT_STR() carries no capture, so its input contract is a string literal or
//  an array with static storage duration: a function-local array is an odr-use
//  of a variable the lambda cannot capture, and does not compile. These two
//  sites pin that contract down - anything that made the macro capture (a
//  `[&]`, say) would break them, and with them every namespace-scope use.
const char kStaticStorageArray[] = "static storage array";
static const auto kLiteralSite = CRYPT_STR("namespace scope literal");
static const auto kArraySite = CRYPT_STR(kStaticStorageArray);

// ---------------------------------------------------------------------------
//  Compile-time proofs
// ---------------------------------------------------------------------------

// plain -> cipher -> plain must be the identity, and re-encrypting that plain
// text must reproduce the original ciphertext byte for byte. On top of that the
// ciphertext has to survive the decode: the inverse writes into a buffer of its
// own, so a decode cannot overwrite the encrypted bytes it read.
// The transform helpers take pointers, so CharType and Size are supplied
// explicitly (they cannot be deduced from a plain pointer argument).
template <typename FlavourT, uint32_t Seed, typename CharType, size_t Size>
constexpr bool roundtrip_seed(const CharType (&plaintext)[Size]) noexcept {
    CharType cipher[Size] = {};
    CharType cipher_copy[Size] = {};
    CharType plain_out[Size] = {};
    CharType reencrypted[Size] = {};

    DynamicCrypter::detail::transform_forward<FlavourT, Seed, CharType, Size>(cipher, plaintext);

    for (size_t i = 0; i < Size; ++i) {
        cipher_copy[i] = cipher[i];
    }

    DynamicCrypter::detail::transform_inverse<FlavourT, Seed, CharType, Size>(plain_out, cipher);
    for (size_t i = 0; i < Size; ++i) {
        if (plain_out[i] != plaintext[i]) {
            return false;
        }
    }

    // Nothing was decoded in place: the ciphertext reads back exactly as it was.
    for (size_t i = 0; i < Size; ++i) {
        if (cipher[i] != cipher_copy[i]) {
            return false;
        }
    }

    DynamicCrypter::detail::transform_forward<FlavourT, Seed, CharType, Size>(reencrypted,
                                                                             plain_out);
    for (size_t i = 0; i < Size; ++i) {
        if (reencrypted[i] != cipher_copy[i]) {
            return false;
        }
    }

    return true;
}

// The key schedule depends on the seed, so every flavour is checked against
// several of them, including both edge values.
template <typename FlavourT, typename CharType, size_t Size>
constexpr bool roundtrip(const CharType (&plaintext)[Size]) noexcept {
    return roundtrip_seed<FlavourT, 0x00000000u>(plaintext) &&
           roundtrip_seed<FlavourT, 0x00000001u>(plaintext) &&
           roundtrip_seed<FlavourT, 0x00C0FFEEu>(plaintext) &&
           roundtrip_seed<FlavourT, 0xFFFFFFFFu>(plaintext);
}

// One static_assert per flavour, so a failure names the exact dimensions that
// broke instead of reporting "something in the product space is wrong".
#define CHECK_FLAVOUR(keygen_name, combiner_name, mode_name, order_name, literal)              \
    static_assert(                                                                             \
        roundtrip<F<Keygen::keygen_name, Combiner::combiner_name, Mode::mode_name,             \
                     Order::order_name>>(literal),                                             \
        "round trip failed: " #keygen_name "/" #combiner_name "/" #mode_name "/" #order_name   \
        " on " #literal " (seeds 0x0, 0x1, 0xC0FFEE, 0xFFFFFFFF)")

// -- every keystream generator ---------------------------------------------
CHECK_FLAVOUR(seed_xor, bit_xor, stream, forward, kShort);
CHECK_FLAVOUR(lcg, bit_xor, stream, forward, kShort);
CHECK_FLAVOUR(xorshift, mul_odd, cbc, backward, kShort);
CHECK_FLAVOUR(splitmix, sbox, cfb, evens_first, kShort);
CHECK_FLAVOUR(crc32c, bit_xor, stream, forward, kShort);
CHECK_FLAVOUR(mul_high, nibble_swap, cbc, odds_first, kShort);
CHECK_FLAVOUR(murmur, add, cfb, rotate, kShort);
CHECK_FLAVOUR(rev_counter, feistel, stream, backward, kShort);

// -- every combiner --------------------------------------------------------
CHECK_FLAVOUR(seed_xor, bit_xor, stream, forward, kShort);
CHECK_FLAVOUR(lcg, add, cbc, forward, kShort);
CHECK_FLAVOUR(murmur, sub, cfb, backward, kShort);
CHECK_FLAVOUR(seed_xor, rotl_add, stream, forward, kShort);
CHECK_FLAVOUR(xorshift, mul_odd, cbc, evens_first, kShort);
CHECK_FLAVOUR(seed_xor, feistel, stream, forward, kShort);
CHECK_FLAVOUR(splitmix, bitrev, cfb, rotate, kShort);
CHECK_FLAVOUR(crc32c, nibble_swap, stream, odds_first, kShort);
CHECK_FLAVOUR(seed_xor, not_xor, stream, forward, kShort);
CHECK_FLAVOUR(lcg, sbox, cbc, backward, kShort);

// -- every mode ------------------------------------------------------------
CHECK_FLAVOUR(splitmix, bit_xor, stream, rotate, kShort);
CHECK_FLAVOUR(seed_xor, sbox, cbc, odds_first, kShort);
CHECK_FLAVOUR(xorshift, feistel, cfb, evens_first, kShort);

// -- every processing order ------------------------------------------------
CHECK_FLAVOUR(seed_xor, bit_xor, stream, forward, kShort);
CHECK_FLAVOUR(seed_xor, bit_xor, stream, backward, kShort);
CHECK_FLAVOUR(seed_xor, bit_xor, stream, rotate, kShort);
CHECK_FLAVOUR(seed_xor, bit_xor, stream, evens_first, kShort);
CHECK_FLAVOUR(seed_xor, bit_xor, stream, odds_first, kShort);

// -- every character type --------------------------------------------------
CHECK_FLAVOUR(splitmix, sbox, cfb, backward, kWide);
CHECK_FLAVOUR(xorshift, mul_odd, cbc, odds_first, kWide);
CHECK_FLAVOUR(murmur, nibble_swap, cfb, evens_first, kU16);
CHECK_FLAVOUR(splitmix, feistel, cbc, backward, kU16);
CHECK_FLAVOUR(crc32c, sbox, stream, rotate, kU32);
CHECK_FLAVOUR(rev_counter, bitrev, cfb, odds_first, kU32);

// -- the eight classic presets, on a longer string -------------------------
CHECK_FLAVOUR(seed_xor, bit_xor, stream, forward, kLong);
CHECK_FLAVOUR(seed_xor, rotl_add, stream, forward, kLong);
CHECK_FLAVOUR(seed_xor, mul_odd, stream, forward, kLong);
CHECK_FLAVOUR(seed_xor, bit_xor, cbc, forward, kLong);
CHECK_FLAVOUR(seed_xor, not_xor, stream, forward, kLong);
CHECK_FLAVOUR(crc32c, bit_xor, stream, forward, kLong);
CHECK_FLAVOUR(seed_xor, feistel, stream, forward, kLong);
CHECK_FLAVOUR(lcg, bit_xor, stream, forward, kLong);

// -- edge cases: empty string, single character, non-ASCII wide -------------
CHECK_FLAVOUR(seed_xor, bit_xor, stream, forward, "");
CHECK_FLAVOUR(splitmix, sbox, cbc, backward, "x");
CHECK_FLAVOUR(lcg, mul_odd, cfb, rotate, L"\u00e9");
CHECK_FLAVOUR(mul_high, feistel, cbc, odds_first, "");

#undef CHECK_FLAVOUR

// ---------------------------------------------------------------------------
//  A spread of combinations across the whole product space
// ---------------------------------------------------------------------------
//  Every individual dimension value is covered exhaustively above, and the
//  dimensions are independent by construction: the keystream is materialised
//  before the mode runs, the combiner is a per-character map, and the order is
//  a permutation. This sweep checks that the four of them still compose
//  correctly when combined, on a bounded sample of the product.
constexpr size_t kKeygens = static_cast<size_t>(Keygen::count);
constexpr size_t kCombiners = static_cast<size_t>(Combiner::count);
constexpr size_t kModes = static_cast<size_t>(Mode::count);
constexpr size_t kOrders = static_cast<size_t>(Order::count);
constexpr size_t kProduct = kKeygens * kCombiners * kModes * kOrders;
constexpr size_t kSamples = 12u;
// 1031 is prime and shares no factor with kProduct's 2/3/5, so this visits
// distinct, well spread points of the product space.
constexpr size_t kSampleStride = 1031u;

template <size_t Sample, typename CharType, size_t Size>
constexpr bool sweep_sample(const CharType (&plaintext)[Size]) noexcept {
    if constexpr (Sample >= kSamples) {
        return true;
    } else {
        constexpr size_t index = (Sample * kSampleStride) % kProduct;
        constexpr Keygen kg = static_cast<Keygen>(index % kKeygens);
        constexpr Combiner cb = static_cast<Combiner>((index / kKeygens) % kCombiners);
        constexpr Mode md = static_cast<Mode>((index / (kKeygens * kCombiners)) % kModes);
        constexpr Order od =
            static_cast<Order>((index / (kKeygens * kCombiners * kModes)) % kOrders);
        return roundtrip<F<kg, cb, md, od>>(plaintext) && sweep_sample<Sample + 1u>(plaintext);
    }
}

static_assert(kProduct == 1200u, "the dimension space changed: update this test");
static_assert(sweep_sample<0u>(kTiny), "a sampled dimension combination does not round-trip");

// ---------------------------------------------------------------------------
//  The site hash has to be a pure function of its arguments: it must vary with
//  the source position and with the counter, and it must not consume
//  __COUNTER__ itself (that is what made half of the flavours unreachable in an
//  earlier revision).
// ---------------------------------------------------------------------------
static_assert(CRYPTER_SITE_HASH(10, 5) != CRYPTER_SITE_HASH(11, 5),
              "the site hash ignores the line number");
static_assert(CRYPTER_SITE_HASH(10, 5) != CRYPTER_SITE_HASH(10, 6),
              "the site hash ignores the counter");

// Both multipliers are odd by design: an even one would push the low bit of its
// product to zero before mix32() ever sees it, so the invariant is proved here
// rather than left to a comment (0x1E35A, the line multiplier this started as,
// looks odd at a glance and is not).
static_assert((DynamicCrypter::detail::kSiteHashLineMultiplier % 2u) == 1u,
              "the site-hash line multiplier must be odd");
static_assert((DynamicCrypter::detail::kSiteHashCounterMultiplier % 2u) == 1u,
              "the site-hash counter multiplier must be odd");

// ---------------------------------------------------------------------------
//  The per-build salt has to reach the key material. mix32 is a bijection, so
//  two different salts over the same source position must give two different
//  hashes.
// ---------------------------------------------------------------------------
static_assert(CRYPTER_SITE_HASH_EX(1, 1, 0x00000000u) != CRYPTER_SITE_HASH_EX(1, 1, 0x12345678u),
              "the per-build salt does not reach the site hash");
static_assert(CRYPTER_SITE_HASH_EX(1, 1, 0x12345678u) != CRYPTER_SITE_HASH_EX(1, 1, 0x87654321u),
              "the per-build salt does not reach the site hash");
static_assert(CRYPTER_SITE_HASH(1, 1) == CRYPTER_SITE_HASH_EX(1, 1, CRYPTER_BUILD_SALT),
              "CRYPTER_SITE_HASH does not fold in CRYPTER_BUILD_SALT");

// ---------------------------------------------------------------------------
//  Over 256 sites, the automatic selection has to reach every value of every
//  dimension. A degenerate slice (say, a combiner that is always bit_xor) would
//  silently shrink the flavour space back down.
// ---------------------------------------------------------------------------
constexpr bool selection_covers_all_dimensions() noexcept {
    bool keygens[static_cast<size_t>(Keygen::count)] = {};
    bool combiners[static_cast<size_t>(Combiner::count)] = {};
    bool modes[static_cast<size_t>(Mode::count)] = {};
    bool orders[static_cast<size_t>(Order::count)] = {};

    for (uint32_t i = 1u; i <= 256u; ++i) {
        const uint32_t hash = DynamicCrypter::detail::mix32(i);
        keygens[static_cast<size_t>(DynamicCrypter::detail::select_keygen(hash))] = true;
        combiners[static_cast<size_t>(DynamicCrypter::detail::select_combiner(hash))] = true;
        modes[static_cast<size_t>(DynamicCrypter::detail::select_mode(hash))] = true;
        orders[static_cast<size_t>(DynamicCrypter::detail::select_order(hash))] = true;
    }

    for (size_t i = 0; i < static_cast<size_t>(Keygen::count); ++i) {
        if (!keygens[i]) {
            return false;
        }
    }
    for (size_t i = 0; i < static_cast<size_t>(Combiner::count); ++i) {
        if (!combiners[i]) {
            return false;
        }
    }
    for (size_t i = 0; i < static_cast<size_t>(Mode::count); ++i) {
        if (!modes[i]) {
            return false;
        }
    }
    for (size_t i = 0; i < static_cast<size_t>(Order::count); ++i) {
        if (!orders[i]) {
            return false;
        }
    }
    return true;
}

static_assert(selection_covers_all_dimensions(),
              "the automatic flavour selection does not reach every dimension value");

// ---------------------------------------------------------------------------
//  The S-box, proved rather than asserted only where it happens to be used
// ---------------------------------------------------------------------------
//  sbox_word() already carries the bijection static_assert internally, but it
//  only fires for the character widths that actually select the S-box combiner.
//  These restate it unconditionally, prove that the two tables invert each
//  other over the whole byte range, and pin the result to the published AES
//  S-box so that a change to the construction cannot pass unnoticed.
static_assert(DynamicCrypter::detail::sbox_is_bijection(),
              "the S-box construction is not a bijection");

constexpr bool sbox_round_trips_every_byte() noexcept {
    for (unsigned i = 0; i < 256u; ++i) {
        const uint8_t byte = static_cast<uint8_t>(i);
        if (DynamicCrypter::detail::sbox_word_inverse(
                DynamicCrypter::detail::sbox_word<uint8_t>(byte)) != byte) {
            return false;
        }
    }
    return true;
}
static_assert(sbox_round_trips_every_byte(),
              "the inverse S-box does not undo the forward S-box");

// Known answers from FIPS-197 (the AES S-box and its inverse).
static_assert(DynamicCrypter::detail::g_sbox.forward[0x00] == 0x63, "AES S-box[0x00]");
static_assert(DynamicCrypter::detail::g_sbox.forward[0x01] == 0x7C, "AES S-box[0x01]");
static_assert(DynamicCrypter::detail::g_sbox.forward[0x53] == 0xED, "AES S-box[0x53]");
static_assert(DynamicCrypter::detail::g_sbox.forward[0xFF] == 0x16, "AES S-box[0xFF]");
static_assert(DynamicCrypter::detail::g_sbox.inverse[0x63] == 0x00, "AES inverse S-box[0x63]");
static_assert(DynamicCrypter::detail::g_sbox.inverse[0xED] == 0x53, "AES inverse S-box[0xED]");

// ---------------------------------------------------------------------------
//  Runtime helpers
// ---------------------------------------------------------------------------
// Re-enters one single CRYPT_STR() call site while the previous object from
// that same site is still alive. Every object owns its own buffer, so the
// re-entrant ones cannot disturb the outer one. Returns the number of failed
// checks.
int nest_same_site(int depth) {
    auto view = CRYPT_STR("same site, overlapping lifetimes");
    int problems = same_text(view.get(), "same site, overlapping lifetimes") ? 0 : 1;
    if (depth > 0) {
        problems += nest_same_site(depth - 1);
    }
    // The outer object must still read correctly once the recursion unwinds.
    if (!same_text(view.get(), "same site, overlapping lifetimes")) {
        ++problems;
    }
    return problems;
}

// The object model, checked end to end: decoding lands in the object's own
// buffer and leaves the site's ciphertext byte for byte as it was, encrypt()
// puts ciphertext back in that same buffer, any read decodes it again, and
// clear() ends the string for good. Returns the number of failed checks.
template <typename CharType, size_t Size, typename FlavourT, uint32_t Seed>
int crypter_checks(const CharType (&plaintext)[Size]) {
    using Cipher = DynamicCrypter::EncryptedString<CharType, Size, FlavourT, Seed>;
    using Object = DynamicCrypter::Crypter<CharType, Size, FlavourT, Seed>;

    int problems = 0;
    const Cipher site(plaintext);

    CharType cipher[Size] = {};
    for (size_t i = 0; i < Size; ++i) {
        cipher[i] = site.data()[i];
    }

    // A fresh object holds the plaintext, in storage of its own.
    Object text(site);
    if (!same_text(text.get(), plaintext) || text.isEncrypted()) {
        ++problems;
    }
    if (text.get() == site.data()) {
        ++problems;
    }
    for (size_t i = 0; i < Size; ++i) {
        if (site.data()[i] != cipher[i]) {
            ++problems;
        }
    }

    // encrypt() hides it again - in the object's buffer, not the site's - and
    // the next read decodes without any further call.
    text.encrypt();
    if (!text.isEncrypted() || !same_text(text.get(), plaintext) || text.isEncrypted()) {
        ++problems;
    }
    for (size_t i = 0; i < Size; ++i) {
        if (site.data()[i] != cipher[i]) {
            ++problems;
        }
    }

    // decrypt() is the explicit form of the same read, and clear() is final:
    // a cleared object stays empty even if it is encrypted or decrypted again.
    text.decrypt();
    if (!same_text(text.get(), plaintext)) {
        ++problems;
    }
    text.clear();
    text.decrypt();
    text.encrypt();
    if (text.isEncrypted()) {
        ++problems;
    }
    for (size_t i = 0; i < Size; ++i) {
        if (text.get()[i] != static_cast<CharType>(0)) {
            ++problems;
        }
    }

    return problems;
}

// Full cycle through the core engine for one flavour, at run time: decode into a
// buffer of its own, check the ciphertext is still intact, then decode it again
// and get the same plaintext back.
template <typename FlavourT, typename CharType, size_t Size>
bool runtime_roundtrip(const CharType (&plaintext)[Size]) {
    DynamicCrypter::EncryptedString<CharType, Size, FlavourT, 0x51ED270Bu> s(plaintext);

    CharType cipher[Size] = {};
    for (size_t i = 0; i < Size; ++i) {
        cipher[i] = s.data()[i];
    }

    CharType decoded[Size] = {};
    s.decrypt(decoded);
    if (!same_text(decoded, plaintext)) {
        return false;
    }

    for (size_t i = 0; i < Size; ++i) {
        if (s.data()[i] != cipher[i]) {
            return false;
        }
    }

    CharType decoded_again[Size] = {};
    s.decrypt(decoded_again);
    return same_text(decoded_again, plaintext);
}

#define CHECK_RUNTIME(label, keygen_name, combiner_name, mode_name, order_name, literal)        \
    report(label,                                                                               \
           runtime_roundtrip<F<Keygen::keygen_name, Combiner::combiner_name,                    \
                               Mode::mode_name, Order::order_name>>(literal))

} // namespace

int main() {
    std::printf("[+] DynamicCrypter test initialised.\n");
    std::printf("    %zu dimension combinations (%zu x %zu x %zu x %zu)\n",
                kProduct, kKeygens, kCombiners, kModes, kOrders);
    std::printf("    build salt: 0x%08X%s\n\n", static_cast<unsigned>(CRYPTER_BUILD_SALT),
                (static_cast<unsigned>(CRYPTER_BUILD_SALT) == 0u) ? " (deterministic)" : "");

    // -----------------------------------------------------------------------
    //  1. Every classic preset through the core engine, at run time
    // -----------------------------------------------------------------------
    std::printf("[:] classic presets through EncryptedString<>\n");
    CHECK_RUNTIME("preset classic_0", seed_xor, bit_xor, stream, forward, kShort);
    CHECK_RUNTIME("preset classic_1", seed_xor, rotl_add, stream, forward, kShort);
    CHECK_RUNTIME("preset classic_2", seed_xor, mul_odd, stream, forward, kShort);
    CHECK_RUNTIME("preset classic_3", seed_xor, bit_xor, cbc, forward, kShort);
    CHECK_RUNTIME("preset classic_4", seed_xor, not_xor, stream, forward, kShort);
    CHECK_RUNTIME("preset classic_5", crc32c, bit_xor, stream, forward, kShort);
    CHECK_RUNTIME("preset classic_6", seed_xor, feistel, stream, forward, kShort);
    CHECK_RUNTIME("preset classic_7", lcg, bit_xor, stream, forward, kShort);

    // Widest spread of the new dimensions at run time.
    CHECK_RUNTIME("splitmix/sbox/cfb/evens_first", splitmix, sbox, cfb, evens_first, kShort);
    CHECK_RUNTIME("murmur/nibble_swap/cbc/odds_first", murmur, nibble_swap, cbc, odds_first, kShort);
    CHECK_RUNTIME("rev_counter/bitrev/cfb/rotate", rev_counter, bitrev, cfb, rotate, kShort);
    CHECK_RUNTIME("mul_high/sub/cbc/backward (wide)", mul_high, sub, cbc, backward, kWide);
    CHECK_RUNTIME("xorshift/bit_xor/cfb/backward (u16)", xorshift, bit_xor, cfb, backward, kU16);
    CHECK_RUNTIME("crc32c/sbox/cbc/forward (u32)", crc32c, sbox, cbc, forward, kU32);

    // The presets must actually name the dimensions they claim to.
    static_assert(DynamicCrypter::Presets::classic_3::mode == Mode::cbc,
                  "classic_3 is documented as chained");
    static_assert(DynamicCrypter::Presets::classic_5::keygen == Keygen::crc32c,
                  "classic_5 is documented as the CRC-32C keystream");
    static_assert(DynamicCrypter::Presets::classic_6::combiner == Combiner::feistel,
                  "classic_6 is documented as the Feistel combiner");

    // -----------------------------------------------------------------------
    //  2. The encrypted form really is encrypted, and per-site seeds differ
    // -----------------------------------------------------------------------
    std::printf("\n[:] the ciphertext is not the plaintext\n");
    {
        // XOR against (seed ^ i) | 1: the key of index 0 cannot be zero, so the
        // first character is guaranteed to change.
        DynamicCrypter::EncryptedString<char, sizeof(kShort),
                                         DynamicCrypter::Presets::classic_0, 0x1234u> s(kShort);
        report("ciphertext differs from plaintext", !same_text(s.data(), kShort));
    }
    {
        DynamicCrypter::EncryptedString<char, sizeof(kShort),
                                         DynamicCrypter::Presets::classic_0, 0x00000001u> first(kShort);
        DynamicCrypter::EncryptedString<char, sizeof(kShort),
                                         DynamicCrypter::Presets::classic_0, 0x00000002u> second(kShort);
        report("a different seed yields a different binary", !same_text(first.data(), second.data()));
    }

    // -----------------------------------------------------------------------
    //  3. CRYPT_STR() - one object, one string
    // -----------------------------------------------------------------------
    std::printf("\n[:] CRYPT_STR()\n");

    {
        auto message = CRYPT_STR("Hello World! This uses one polymorphic flavour.");
        report("decrypts", same_text(message.get(), "Hello World! This uses one polymorphic flavour."));
        // same_text() deduces its type from a pointer, so a user defined
        // conversion is not considered - the conversion has to happen first.
        const char* as_pointer = message;
        report("implicit conversion", same_text(as_pointer, "Hello World! This uses one polymorphic flavour."));
        report("exposes the full length",
               message.size() == sizeof("Hello World! This uses one polymorphic flavour."));
    }

    {
        auto hosted = CRYPT_STR("https://secure-endpoint.local");
        report("valid while its object lives",
               same_text(hosted.get(), "https://secure-endpoint.local"));
    }

    // Sites at namespace scope: the macro's lambda captures nothing, so a
    // literal and an array with static storage duration are the whole contract.
    report("a namespace scope literal", same_text(kLiteralSite.get(), "namespace scope literal"));
    report("a static storage array", same_text(kArraySite.get(), kStaticStorageArray));

    {
        auto wide = CRYPT_STR(L"Wide-String Hello Protection");
        report("wchar_t round trip", same_text(wide.get(), L"Wide-String Hello Protection"));
        std::wcout << L"    streamed: " << wide.get() << std::endl;
    }

    std::cout << "    streamed: " << CRYPT_STR("straight into std::cout") << std::endl;
    // Variadic argument lists do not apply user defined conversions, so
    // printf-style APIs need .get().
    std::printf("    streamed: %s\n", CRYPT_STR("into printf via .get()").get());

    // -----------------------------------------------------------------------
    //  4. The object owns the string: decode, hide, clear
    // -----------------------------------------------------------------------
    std::printf("\n[:] one object, one string it owns\n");

    report("a site stays ciphertext, the object owns the text",
           crypter_checks<char, sizeof("decoded into the object, not the blob"),
                          DynamicCrypter::FlavourOf<0x5EED1234u>, 0x5EED1234u>(
               "decoded into the object, not the blob") == 0);
    report("the same holds for wide characters",
           crypter_checks<wchar_t, sizeof(L"wide, and still the object's own") / sizeof(wchar_t),
                          DynamicCrypter::Presets::classic_3, 0x00C0FFEEu>(
               L"wide, and still the object's own") == 0);

    {
        // The same state machine through the macro: encrypt() hides the text
        // again inside the object's own buffer, a read decodes it back, and
        // clear() is the end of the string.
        auto message = CRYPT_STR("encrypt, read, clear");
        report("reads decode", same_text(message.get(), "encrypt, read, clear"));

        message.encrypt();
        report("encrypt() reports ciphertext", message.isEncrypted());
        report("a read decodes it again",
               same_text(message.get(), "encrypt, read, clear") && !message.isEncrypted());

        message.clear();
        report("clear() ends the string",
               !message.isEncrypted() && message.get()[0] == '\0');

        // clear() is terminal and idempotent: a second call has nothing left to
        // wipe, and neither a read nor an encrypt() can bring the string back.
        message.clear();
        message.encrypt();
        report("clear() is idempotent and final",
               !message.isEncrypted() && message.get()[0] == '\0');
    }

    // The destructor runs the same clear() that was just checked, so the wipe
    // itself needs no separate test; reading the buffer after the object dies
    // would be use-after-scope, which is exactly what the sanitizer job exists
    // to catch, so the test suite deliberately does not do it.

    // -----------------------------------------------------------------------
    //  5. Repeated and overlapping use of one call site
    // -----------------------------------------------------------------------
    std::printf("\n[:] repeated use of a single call site\n");

    bool loop_ok = true;
    for (int i = 0; i < 8; ++i) {
        auto repeated = CRYPT_STR("same site every iteration");
        loop_ok = loop_ok && same_text(repeated.get(), "same site every iteration");
    }
    report("CRYPT_STR() in a loop", loop_ok);
    report("CRYPT_STR() re-entered at one site", nest_same_site(4) == 0);

    // -----------------------------------------------------------------------
    //  6. The S-box, on the tables this build actually uses
    // -----------------------------------------------------------------------
    //  The same checks as above, re-run at run time, so that the tables the
    //  program actually reaches are validated as well - not only the ones the
    //  compiler proved while it was evaluating the constant expressions.
    std::printf("\n[:] the S-box tables\n");
    report("forward and inverse form a bijection",
           DynamicCrypter::detail::sbox_is_bijection());
    report("every byte round-trips", sbox_round_trips_every_byte());
    report("still the published AES S-box",
           DynamicCrypter::detail::g_sbox.forward[0x00] == 0x63 &&
               DynamicCrypter::detail::g_sbox.forward[0x53] == 0xED &&
               DynamicCrypter::detail::g_sbox.inverse[0xED] == 0x53);

    if (g_failures == 0) {
        std::printf("\n[+] all checks passed\n");
    } else {
        std::printf("\n[-] %d check(s) FAILED\n", g_failures);
    }

    return g_failures == 0 ? 0 : 1;
}
