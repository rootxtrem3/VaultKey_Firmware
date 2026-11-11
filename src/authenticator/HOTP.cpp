#include "authenticator/HOTP.h"

#include <array>
#include <cstdio>

#include "security/SecureZero.h"

#ifdef VAULTKEY_HOST_TEST
#include <openssl/evp.h>
#include <openssl/hmac.h>
#else
#include <mbedtls/md.h>
#endif

namespace vaultkey {
namespace {

std::size_t digestLength(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::Sha1:
            return 20;
        case HashAlgorithm::Sha256:
            return 32;
        case HashAlgorithm::Sha512:
            return 64;
    }
    return 0;
}

bool hmac(HashAlgorithm algorithm, const uint8_t* key, std::size_t keyLength,
          const uint8_t* message, std::size_t messageLength, uint8_t* output) {
#ifdef VAULTKEY_HOST_TEST
    const EVP_MD* md = nullptr;
    switch (algorithm) {
        case HashAlgorithm::Sha1:
            md = EVP_sha1();
            break;
        case HashAlgorithm::Sha256:
            md = EVP_sha256();
            break;
        case HashAlgorithm::Sha512:
            md = EVP_sha512();
            break;
    }
    unsigned int length = 0;
    return md != nullptr &&
           HMAC(md, key, static_cast<int>(keyLength), message, messageLength,
                output, &length) != nullptr &&
           length == digestLength(algorithm);
#else
    mbedtls_md_type_t type = MBEDTLS_MD_NONE;
    switch (algorithm) {
        case HashAlgorithm::Sha1:
            type = MBEDTLS_MD_SHA1;
            break;
        case HashAlgorithm::Sha256:
            type = MBEDTLS_MD_SHA256;
            break;
        case HashAlgorithm::Sha512:
            type = MBEDTLS_MD_SHA512;
            break;
    }
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(type);
    return info != nullptr &&
           mbedtls_md_hmac(info, key, keyLength, message, messageLength,
                           output) == 0;
#endif
}

uint32_t modulus(uint8_t digits) {
    return digits == 6 ? 1000000U : 100000000U;
}

}  // namespace

bool HOTP::generate(const uint8_t* secret, std::size_t secretLength,
                    uint64_t counter, HashAlgorithm algorithm, uint8_t digits,
                    uint32_t& code) {
    if (secret == nullptr || secretLength == 0 || secretLength > 64 ||
        (digits != 6 && digits != 8) || digestLength(algorithm) == 0) {
        return false;
    }

    std::array<uint8_t, 8> counterBytes{};
    for (int index = 7; index >= 0; --index) {
        counterBytes[static_cast<std::size_t>(index)] =
            static_cast<uint8_t>(counter);
        counter >>= 8U;
    }

    std::array<uint8_t, 64> digest{};
    if (!hmac(algorithm, secret, secretLength, counterBytes.data(),
              counterBytes.size(), digest.data())) {
        secureZero(digest.data(), digest.size());
        return false;
    }

    const std::size_t length = digestLength(algorithm);
    const uint8_t offset = digest[length - 1] & 0x0FU;
    if (static_cast<std::size_t>(offset) + 3 >= length) {
        secureZero(digest.data(), digest.size());
        return false;
    }
    const uint32_t truncated =
        (static_cast<uint32_t>(digest[offset] & 0x7FU) << 24U) |
        (static_cast<uint32_t>(digest[offset + 1]) << 16U) |
        (static_cast<uint32_t>(digest[offset + 2]) << 8U) |
        static_cast<uint32_t>(digest[offset + 3]);
    code = truncated % modulus(digits);
    secureZero(digest.data(), digest.size());
    secureZero(counterBytes.data(), counterBytes.size());
    return true;
}

bool HOTP::format(uint32_t code, uint8_t digits, std::string& output) {
    if (digits != 6 && digits != 8) return false;
    char buffer[9]{};
    const int written = std::snprintf(buffer, sizeof(buffer), "%0*u", digits,
                                      static_cast<unsigned>(code));
    if (written != digits) {
        secureZero(buffer, sizeof(buffer));
        return false;
    }
    output.assign(buffer, static_cast<std::size_t>(written));
    secureZero(buffer, sizeof(buffer));
    return true;
}

}  // namespace vaultkey
