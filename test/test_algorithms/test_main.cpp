#include <unity.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "authenticator/OtpAuth.h"
#include "authenticator/HOTP.h"
#include "authenticator/TOTP.h"
#include "core/TimeUtils.h"
#include "security/Crypto.h"
#include "security/SecureZero.h"
#include "vault/RecordCodec.h"

using namespace vaultkey;

namespace {

std::vector<uint8_t> bytes(const char* value) {
    return std::vector<uint8_t>(value, value + std::strlen(value));
}

void assertTotp(const std::vector<uint8_t>& secret, uint64_t time,
                HashAlgorithm algorithm, const char* expected) {
    std::string output;
    TEST_ASSERT_TRUE(TOTP::generate(secret.data(), secret.size(), time,
                                    algorithm, 8, 30, output));
    TEST_ASSERT_EQUAL_STRING(expected, output.c_str());
}

void test_time_round_trip() {
    CalendarTime value{2026, 11, 13, 6, 18, 42, 35};
    uint64_t unixTime = 0;
    TEST_ASSERT_TRUE(TimeUtils::valid(value));
    TEST_ASSERT_TRUE(TimeUtils::toUnix(value, unixTime));
    TEST_ASSERT_EQUAL_UINT64(1794595355ULL, unixTime);
    CalendarTime decoded;
    TEST_ASSERT_TRUE(TimeUtils::fromUnix(unixTime, decoded));
    TEST_ASSERT_EQUAL_UINT16(2026, decoded.year);
    TEST_ASSERT_EQUAL_UINT8(11, decoded.month);
    TEST_ASSERT_EQUAL_UINT8(13, decoded.day);
    TEST_ASSERT_EQUAL_UINT8(6, decoded.weekday);
    TEST_ASSERT_EQUAL_UINT8(18, decoded.hour);
    TEST_ASSERT_EQUAL_UINT8(42, decoded.minute);
    TEST_ASSERT_EQUAL_UINT8(35, decoded.second);
}

void test_time_leap_and_invalid() {
    CalendarTime leap{2024, 2, 29, 5, 23, 59, 59};
    uint64_t unixTime = 0;
    TEST_ASSERT_TRUE(TimeUtils::toUnix(leap, unixTime));
    CalendarTime invalid{2025, 2, 29, 7, 0, 0, 0};
    TEST_ASSERT_FALSE(TimeUtils::valid(invalid));
    TEST_ASSERT_EQUAL_UINT8(29, TimeUtils::daysInMonth(2000, 2));
    TEST_ASSERT_EQUAL_UINT8(28, TimeUtils::daysInMonth(2100, 2));
}

void test_rfc6238_vectors() {
    TEST_ASSERT_TRUE(TOTP::selfTest());
    const auto sha1 = bytes("12345678901234567890");
    const auto sha256 = bytes("12345678901234567890123456789012");
    const auto sha512 = bytes(
        "1234567890123456789012345678901234567890123456789012345678901234");
    struct Vector {
        uint64_t time;
        const char* sha1;
        const char* sha256;
        const char* sha512;
    };
    static constexpr Vector vectors[] = {
        {59, "94287082", "46119246", "90693936"},
        {1111111109ULL, "07081804", "68084774", "25091201"},
        {1111111111ULL, "14050471", "67062674", "99943326"},
        {1234567890ULL, "89005924", "91819424", "93441116"},
        {2000000000ULL, "69279037", "90698825", "38618901"},
        {20000000000ULL, "65353130", "77737706", "47863826"},
    };
    for (const auto& vector : vectors) {
        assertTotp(sha1, vector.time, HashAlgorithm::Sha1, vector.sha1);
        assertTotp(sha256, vector.time, HashAlgorithm::Sha256, vector.sha256);
        assertTotp(sha512, vector.time, HashAlgorithm::Sha512, vector.sha512);
    }

    std::string sixDigits;
    TEST_ASSERT_TRUE(TOTP::generate(sha1.data(), sha1.size(), 1111111109ULL,
                                    HashAlgorithm::Sha1, 6, 30, sixDigits));
    TEST_ASSERT_EQUAL_STRING("081804", sixDigits.c_str());
}

void test_rfc4226_hotp_vectors() {
    const auto secret = bytes("12345678901234567890");
    static constexpr uint32_t expected[] = {
        755224, 287082, 359152, 969429, 338314,
        254676, 287922, 162583, 399871, 520489};
    for (uint64_t counter = 0; counter < 10; ++counter) {
        uint32_t code = 0;
        TEST_ASSERT_TRUE(HOTP::generate(secret, counter, HashAlgorithm::Sha1, 6,
                                        code));
        TEST_ASSERT_EQUAL_UINT32(expected[counter], code);
    }
}

void test_base32_and_otpauth() {
    std::vector<uint8_t> decoded;
    TEST_ASSERT_TRUE(Base32::decode("JBSWY3DPEHPK3PXP", decoded));
    const auto expected = bytes("Hello!\xDE\xAD\xBE\xEF");
    TEST_ASSERT_EQUAL_UINT(expected.size(), decoded.size());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), decoded.data(), expected.size());
    secureClear(decoded);
    TEST_ASSERT_FALSE(Base32::decode("INVALID*", decoded));

    TotpEntry entry;
    std::string error;
    TEST_ASSERT_TRUE(OtpAuth::parse(
        "otpauth://totp/VaultKey%3Aalice%40example.com?secret="
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=VaultKey&algorithm="
        "SHA256&digits=8&period=45",
        entry, error));
    TEST_ASSERT_EQUAL_STRING("VaultKey", entry.issuer.c_str());
    TEST_ASSERT_EQUAL_STRING("alice@example.com", entry.account.c_str());
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(HashAlgorithm::Sha256),
                            static_cast<uint8_t>(entry.algorithm));
    TEST_ASSERT_EQUAL_UINT8(8, entry.digits);
    TEST_ASSERT_EQUAL_UINT16(45, entry.period);
    TEST_ASSERT_FALSE(entry.secret.empty());
    entry.clearSensitive();
}

void test_otpauth_rejects_malformed_input() {
    TotpEntry entry;
    std::string error;
    TEST_ASSERT_FALSE(OtpAuth::parse(
        "otpauth://totp/Issuer:alice?secret=INVALID*&issuer=Issuer", entry,
        error));
    TEST_ASSERT_EQUAL_STRING("invalid_secret", error.c_str());
    TEST_ASSERT_TRUE(entry.secret.empty());
    TEST_ASSERT_FALSE(OtpAuth::parse(
        "otpauth://hotp/Issuer:alice?secret=JBSWY3DPEHPK3PXP", entry,
        error));
}

void test_pbkdf2_and_hkdf_vectors() {
    static constexpr std::array<uint8_t, 32> pbkdfExpected = {
        0x12, 0x0F, 0xB6, 0xCF, 0xFC, 0xF8, 0xB3, 0x2C,
        0x43, 0xE7, 0x22, 0x52, 0x56, 0xC4, 0xF8, 0x37,
        0xA8, 0x65, 0x48, 0xC9, 0x2C, 0xCC, 0x35, 0x48,
        0x08, 0x05, 0x98, 0x7C, 0xB7, 0x0B, 0xE1, 0x7B};
    std::array<uint8_t, 32> derived{};
    TEST_ASSERT_TRUE(Crypto::pbkdf2Sha256(
        reinterpret_cast<const uint8_t*>("password"), 8,
        reinterpret_cast<const uint8_t*>("salt"), 4, 1, derived.data(),
        derived.size()));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pbkdfExpected.data(), derived.data(),
                                  derived.size());

    std::array<uint8_t, 22> ikm{};
    ikm.fill(0x0B);
    const std::array<uint8_t, 13> salt = {0x00, 0x01, 0x02, 0x03, 0x04,
                                          0x05, 0x06, 0x07, 0x08, 0x09,
                                          0x0A, 0x0B, 0x0C};
    const std::array<uint8_t, 10> info = {0xF0, 0xF1, 0xF2, 0xF3, 0xF4,
                                          0xF5, 0xF6, 0xF7, 0xF8, 0xF9};
    const std::array<uint8_t, 42> expected = {
        0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A, 0x90, 0x43, 0x4F,
        0x64, 0xD0, 0x36, 0x2F, 0x2A, 0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A,
        0x5A, 0x4C, 0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4, 0xC5, 0xBF, 0x34,
        0x00, 0x72, 0x08, 0xD5, 0xB8, 0x87, 0x18, 0x58, 0x65};
    std::array<uint8_t, 42> output{};
    TEST_ASSERT_TRUE(Crypto::hkdfSha256(
        ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(),
        info.size(), output.data(), output.size()));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), output.data(), output.size());
    secureZero(derived.data(), derived.size());
    secureZero(output.data(), output.size());
}

void test_aes_gcm_and_authentication_failure() {
    TEST_ASSERT_TRUE(Crypto::selfTest());
    std::array<uint8_t, Crypto::KEY_SIZE> key{};
    std::array<uint8_t, Crypto::NONCE_SIZE> nonce{};
    std::array<uint8_t, 5> plaintext = {1, 2, 3, 4, 5};
    std::array<uint8_t, 5> ciphertext{};
    std::array<uint8_t, Crypto::TAG_SIZE> tag{};
    std::array<uint8_t, 5> result{};
    TEST_ASSERT_TRUE(Crypto::aes256GcmEncrypt(
        key.data(), nonce.data(), nullptr, 0, plaintext.data(), plaintext.size(),
        ciphertext.data(), tag.data()));
    tag[0] ^= 1U;
    result.fill(0xAA);
    TEST_ASSERT_FALSE(Crypto::aes256GcmDecrypt(
        key.data(), nonce.data(), nullptr, 0, ciphertext.data(),
        ciphertext.size(), tag.data(), result.data()));
    const std::array<uint8_t, 5> zeros{};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(zeros.data(), result.data(), result.size());
}

void test_record_codec() {
    Credential original;
    original.id = 42;
    original.service = "Example";
    original.username = "alice";
    original.password = "correct horse battery staple";
    original.url = "https://example.test";
    original.notes = "test";
    original.createdAt = 1700000000ULL;
    std::vector<uint8_t> encoded;
    TEST_ASSERT_TRUE(RecordCodec::encode(original, encoded));
    Credential decoded;
    TEST_ASSERT_TRUE(RecordCodec::decode(encoded, decoded));
    TEST_ASSERT_EQUAL_UINT32(original.id, decoded.id);
    TEST_ASSERT_EQUAL_STRING(original.service.c_str(), decoded.service.c_str());
    TEST_ASSERT_EQUAL_STRING(original.username.c_str(), decoded.username.c_str());
    TEST_ASSERT_EQUAL_STRING(original.password.c_str(), decoded.password.c_str());
    decoded.clearSensitive();
    original.clearSensitive();
    secureClear(encoded);
}

void test_totp_record_codec_and_corruption() {
    TotpEntry original;
    original.id = 77;
    original.issuer = "VaultKey";
    original.account = "alice@example.test";
    original.secret = bytes("12345678901234567890");
    original.algorithm = HashAlgorithm::Sha512;
    original.digits = 8;
    original.period = 45;
    original.createdAt = 1794595355ULL;
    std::vector<uint8_t> encoded;
    TEST_ASSERT_TRUE(RecordCodec::encode(original, encoded));
    TotpEntry decoded;
    TEST_ASSERT_TRUE(RecordCodec::decode(encoded, decoded));
    TEST_ASSERT_EQUAL_UINT32(original.id, decoded.id);
    TEST_ASSERT_EQUAL_STRING(original.issuer.c_str(), decoded.issuer.c_str());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(original.secret.data(), decoded.secret.data(),
                                  original.secret.size());
    encoded.push_back(0xAA);
    TotpEntry corrupt;
    TEST_ASSERT_FALSE(RecordCodec::decode(encoded, corrupt));
    original.clearSensitive();
    decoded.clearSensitive();
    secureClear(encoded);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_time_round_trip);
    RUN_TEST(test_time_leap_and_invalid);
    RUN_TEST(test_rfc6238_vectors);
    RUN_TEST(test_rfc4226_hotp_vectors);
    RUN_TEST(test_base32_and_otpauth);
    RUN_TEST(test_otpauth_rejects_malformed_input);
    RUN_TEST(test_pbkdf2_and_hkdf_vectors);
    RUN_TEST(test_aes_gcm_and_authentication_failure);
    RUN_TEST(test_record_codec);
    RUN_TEST(test_totp_record_codec_and_corruption);
    return UNITY_END();
}
