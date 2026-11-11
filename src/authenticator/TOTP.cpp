#include "authenticator/TOTP.h"

#include <cctype>

#include "authenticator/HOTP.h"
#include "core/HardwareConfig.h"
#include "security/SecureZero.h"

namespace vaultkey {
namespace {

int base32Value(char character) {
    const unsigned char byte = static_cast<unsigned char>(character);
    const char upper = static_cast<char>(std::toupper(byte));
    if (upper >= 'A' && upper <= 'Z') return upper - 'A';
    if (upper >= '2' && upper <= '7') return upper - '2' + 26;
    return -1;
}

}  // namespace

bool TOTP::selfTest() {
    static constexpr uint8_t SHA1_SECRET[] = "12345678901234567890";
    static constexpr uint8_t SHA256_SECRET[] =
        "12345678901234567890123456789012";
    static constexpr uint8_t SHA512_SECRET[] =
        "1234567890123456789012345678901234567890123456789012345678901234";
    struct Vector {
        uint64_t time;
        const char* sha1;
        const char* sha256;
        const char* sha512;
    };
    static constexpr Vector VECTORS[] = {
        {59, "94287082", "46119246", "90693936"},
        {1111111109ULL, "07081804", "68084774", "25091201"},
        {1111111111ULL, "14050471", "67062674", "99943326"},
        {1234567890ULL, "89005924", "91819424", "93441116"},
        {2000000000ULL, "69279037", "90698825", "38618901"},
        {20000000000ULL, "65353130", "77737706", "47863826"},
    };
    std::string output;
    for (const Vector& vector : VECTORS) {
        if (!generate(SHA1_SECRET, sizeof(SHA1_SECRET) - 1, vector.time,
                      HashAlgorithm::Sha1, 8, 30, output) ||
            output != vector.sha1 ||
            !generate(SHA256_SECRET, sizeof(SHA256_SECRET) - 1, vector.time,
                      HashAlgorithm::Sha256, 8, 30, output) ||
            output != vector.sha256 ||
            !generate(SHA512_SECRET, sizeof(SHA512_SECRET) - 1, vector.time,
                      HashAlgorithm::Sha512, 8, 30, output) ||
            output != vector.sha512) {
            secureClear(output);
            return false;
        }
    }
    secureClear(output);
    return true;
}

bool Base32::decode(const std::string& input, std::vector<uint8_t>& output) {
    output.clear();
    if (input.empty() || input.size() > 128) return false;

    uint32_t buffer = 0;
    uint8_t bits = 0;
    bool padding = false;
    std::size_t symbols = 0;
    for (char character : input) {
        if (character == '=') {
            padding = true;
            continue;
        }
        if (padding) {
            secureClear(output);
            return false;
        }
        const int value = base32Value(character);
        if (value < 0) {
            secureClear(output);
            return false;
        }
        ++symbols;
        buffer = (buffer << 5U) | static_cast<uint32_t>(value);
        bits = static_cast<uint8_t>(bits + 5U);
        if (bits >= 8U) {
            bits = static_cast<uint8_t>(bits - 8U);
            if (output.size() >= limits::TOTP_SECRET) {
                secureClear(output);
                return false;
            }
            output.push_back(static_cast<uint8_t>(buffer >> bits));
            if (bits == 0) {
                buffer = 0;
            } else {
                buffer &= (1U << bits) - 1U;
            }
        }
    }

    // RFC 4648 permits unpadded input, but any unused trailing bits must be 0.
    if (symbols == 0 || (bits != 0 && buffer != 0)) {
        secureClear(output);
        return false;
    }
    return !output.empty();
}

bool TOTP::generate(const uint8_t* secret, std::size_t secretLength,
                    uint64_t unixTime, HashAlgorithm algorithm, uint8_t digits,
                    uint16_t period, std::string& output) {
    output.clear();
    if (period == 0) return false;
    uint32_t code = 0;
    if (!HOTP::generate(secret, secretLength, unixTime / period, algorithm,
                        digits, code)) {
        return false;
    }
    return HOTP::format(code, digits, output);
}

uint16_t TOTP::remaining(uint64_t unixTime, uint16_t period) {
    if (period == 0) return 0;
    const uint16_t elapsed = static_cast<uint16_t>(unixTime % period);
    return static_cast<uint16_t>(period - elapsed);
}

}  // namespace vaultkey
