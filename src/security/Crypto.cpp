#include "security/Crypto.h"

#include <array>
#include <cstring>

#include "security/SecureZero.h"

#ifdef VAULTKEY_HOST_TEST
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#else
#include <esp_random.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#endif

namespace vaultkey {

bool Crypto::randomBytes(uint8_t* output, std::size_t length) {
    if (output == nullptr || length == 0) return false;
#ifdef VAULTKEY_HOST_TEST
    return RAND_bytes(output, static_cast<int>(length)) == 1;
#else
    esp_fill_random(output, length);
    return true;
#endif
}

bool Crypto::pbkdf2Sha256(const uint8_t* password,
                          std::size_t passwordLength, const uint8_t* salt,
                          std::size_t saltLength, uint32_t iterations,
                          uint8_t* output, std::size_t outputLength) {
    if (password == nullptr || salt == nullptr || output == nullptr ||
        passwordLength == 0 || saltLength == 0 || outputLength == 0 ||
        iterations == 0) {
        return false;
    }
#ifdef VAULTKEY_HOST_TEST
    return PKCS5_PBKDF2_HMAC(
               reinterpret_cast<const char*>(password),
               static_cast<int>(passwordLength), salt,
               static_cast<int>(saltLength), static_cast<int>(iterations),
               EVP_sha256(), static_cast<int>(outputLength), output) == 1;
#else
    return mbedtls_pkcs5_pbkdf2_hmac_ext(
               MBEDTLS_MD_SHA256, password, passwordLength, salt, saltLength,
               iterations, outputLength, output) == 0;
#endif
}

bool Crypto::hkdfSha256(const uint8_t* inputKey, std::size_t inputKeyLength,
                        const uint8_t* salt, std::size_t saltLength,
                        const uint8_t* info, std::size_t infoLength,
                        uint8_t* output, std::size_t outputLength) {
    if (inputKey == nullptr || inputKeyLength == 0 || output == nullptr ||
        outputLength == 0 || (salt == nullptr && saltLength != 0) ||
        (info == nullptr && infoLength != 0)) {
        return false;
    }
#ifdef VAULTKEY_HOST_TEST
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (context == nullptr) return false;
    std::size_t length = outputLength;
    const bool result =
        EVP_PKEY_derive_init(context) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(context, salt,
                                    static_cast<int>(saltLength)) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(context, inputKey,
                                   static_cast<int>(inputKeyLength)) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(context, info,
                                    static_cast<int>(infoLength)) > 0 &&
        EVP_PKEY_derive(context, output, &length) > 0 && length == outputLength;
    EVP_PKEY_CTX_free(context);
    return result;
#else
    const mbedtls_md_info_t* md =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return md != nullptr &&
           mbedtls_hkdf(md, salt, saltLength, inputKey, inputKeyLength, info,
                        infoLength, output, outputLength) == 0;
#endif
}

bool Crypto::aes256GcmEncrypt(const uint8_t key[KEY_SIZE],
                              const uint8_t nonce[NONCE_SIZE],
                              const uint8_t* aad, std::size_t aadLength,
                              const uint8_t* plaintext,
                              std::size_t plaintextLength, uint8_t* ciphertext,
                              uint8_t tag[TAG_SIZE]) {
    if (key == nullptr || nonce == nullptr || tag == nullptr ||
        (aad == nullptr && aadLength != 0) ||
        (plaintext == nullptr && plaintextLength != 0) ||
        (ciphertext == nullptr && plaintextLength != 0)) {
        return false;
    }
#ifdef VAULTKEY_HOST_TEST
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) return false;
    int length = 0;
    int total = 0;
    bool result = EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr,
                                     nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                                      NONCE_SIZE, nullptr) == 1 &&
                  EVP_EncryptInit_ex(context, nullptr, nullptr, key, nonce) == 1;
    if (result && aadLength != 0) {
        result = EVP_EncryptUpdate(context, nullptr, &length, aad,
                                   static_cast<int>(aadLength)) == 1;
    }
    if (result && plaintextLength != 0) {
        result = EVP_EncryptUpdate(context, ciphertext, &length, plaintext,
                                   static_cast<int>(plaintextLength)) == 1;
        total = length;
    }
    if (result) {
        result = EVP_EncryptFinal_ex(context, ciphertext + total, &length) == 1 &&
                 EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                                     tag) == 1;
    }
    EVP_CIPHER_CTX_free(context);
    return result;
#else
    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);
    const int keyResult = mbedtls_gcm_setkey(
        &context, MBEDTLS_CIPHER_ID_AES, key, KEY_SIZE * 8U);
    const int result =
        keyResult == 0
            ? mbedtls_gcm_crypt_and_tag(
                  &context, MBEDTLS_GCM_ENCRYPT, plaintextLength, nonce,
                  NONCE_SIZE, aad, aadLength, plaintext, ciphertext, TAG_SIZE,
                  tag)
            : keyResult;
    mbedtls_gcm_free(&context);
    return result == 0;
#endif
}

bool Crypto::aes256GcmDecrypt(const uint8_t key[KEY_SIZE],
                              const uint8_t nonce[NONCE_SIZE],
                              const uint8_t* aad, std::size_t aadLength,
                              const uint8_t* ciphertext,
                              std::size_t ciphertextLength,
                              const uint8_t tag[TAG_SIZE], uint8_t* plaintext) {
    if (key == nullptr || nonce == nullptr || tag == nullptr ||
        (aad == nullptr && aadLength != 0) ||
        (ciphertext == nullptr && ciphertextLength != 0) ||
        (plaintext == nullptr && ciphertextLength != 0)) {
        return false;
    }
#ifdef VAULTKEY_HOST_TEST
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) return false;
    int length = 0;
    int total = 0;
    bool result = EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr,
                                     nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                                      NONCE_SIZE, nullptr) == 1 &&
                  EVP_DecryptInit_ex(context, nullptr, nullptr, key, nonce) == 1;
    if (result && aadLength != 0) {
        result = EVP_DecryptUpdate(context, nullptr, &length, aad,
                                   static_cast<int>(aadLength)) == 1;
    }
    if (result && ciphertextLength != 0) {
        result = EVP_DecryptUpdate(context, plaintext, &length, ciphertext,
                                   static_cast<int>(ciphertextLength)) == 1;
        total = length;
    }
    if (result) {
        result = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                                     const_cast<uint8_t*>(tag)) == 1 &&
                 EVP_DecryptFinal_ex(context, plaintext + total, &length) == 1;
    }
    EVP_CIPHER_CTX_free(context);
#else
    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);
    const int keyResult = mbedtls_gcm_setkey(
        &context, MBEDTLS_CIPHER_ID_AES, key, KEY_SIZE * 8U);
    const bool result =
        keyResult == 0 &&
        mbedtls_gcm_auth_decrypt(&context, ciphertextLength, nonce, NONCE_SIZE,
                                 aad, aadLength, tag, TAG_SIZE, ciphertext,
                                 plaintext) == 0;
    mbedtls_gcm_free(&context);
#endif
    if (!result && plaintext != nullptr && ciphertextLength != 0) {
        secureZero(plaintext, ciphertextLength);
    }
    return result;
}

bool Crypto::constantTimeEqual(const uint8_t* left, const uint8_t* right,
                               std::size_t length) {
    if (left == nullptr || right == nullptr) return false;
    uint8_t difference = 0;
    for (std::size_t index = 0; index < length; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}

bool Crypto::selfTest() {
    static constexpr std::array<uint8_t, 32> key{};
    static constexpr std::array<uint8_t, 12> nonce{};
    static constexpr std::array<uint8_t, 16> plaintext{};
    static constexpr std::array<uint8_t, 16> expectedCiphertext = {
        0xCE, 0xA7, 0x40, 0x3D, 0x4D, 0x60, 0x6B, 0x6E,
        0x07, 0x4E, 0xC5, 0xD3, 0xBA, 0xF3, 0x9D, 0x18};
    static constexpr std::array<uint8_t, 16> expectedTag = {
        0xD0, 0xD1, 0xC8, 0xA7, 0x99, 0x99, 0x6B, 0xF0,
        0x26, 0x5B, 0x98, 0xB5, 0xD4, 0x8A, 0xB9, 0x19};

    std::array<uint8_t, 16> ciphertext{};
    std::array<uint8_t, 16> tag{};
    std::array<uint8_t, 16> decrypted{};
    bool ok = aes256GcmEncrypt(key.data(), nonce.data(), nullptr, 0,
                               plaintext.data(), plaintext.size(),
                               ciphertext.data(), tag.data()) &&
              constantTimeEqual(ciphertext.data(), expectedCiphertext.data(),
                                ciphertext.size()) &&
              constantTimeEqual(tag.data(), expectedTag.data(), tag.size()) &&
              aes256GcmDecrypt(key.data(), nonce.data(), nullptr, 0,
                               ciphertext.data(), ciphertext.size(), tag.data(),
                               decrypted.data()) &&
               constantTimeEqual(decrypted.data(), plaintext.data(),
                                 plaintext.size());

    static constexpr std::array<uint8_t, 32> expectedPbkdf2 = {
        0x12, 0x0F, 0xB6, 0xCF, 0xFC, 0xF8, 0xB3, 0x2C,
        0x43, 0xE7, 0x22, 0x52, 0x56, 0xC4, 0xF8, 0x37,
        0xA8, 0x65, 0x48, 0xC9, 0x2C, 0xCC, 0x35, 0x48,
        0x08, 0x05, 0x98, 0x7C, 0xB7, 0x0B, 0xE1, 0x7B};
    std::array<uint8_t, 32> pbkdf2{};
    ok = ok && pbkdf2Sha256(
                   reinterpret_cast<const uint8_t*>("password"), 8,
                   reinterpret_cast<const uint8_t*>("salt"), 4, 1,
                   pbkdf2.data(), pbkdf2.size()) &&
         constantTimeEqual(pbkdf2.data(), expectedPbkdf2.data(), pbkdf2.size());

    std::array<uint8_t, 22> ikm{};
    ikm.fill(0x0B);
    static constexpr std::array<uint8_t, 13> hkdfSalt = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
    static constexpr std::array<uint8_t, 10> hkdfInfo = {
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4,
        0xF5, 0xF6, 0xF7, 0xF8, 0xF9};
    static constexpr std::array<uint8_t, 42> expectedHkdf = {
        0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A, 0x90, 0x43, 0x4F,
        0x64, 0xD0, 0x36, 0x2F, 0x2A, 0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A,
        0x5A, 0x4C, 0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4, 0xC5, 0xBF, 0x34,
        0x00, 0x72, 0x08, 0xD5, 0xB8, 0x87, 0x18, 0x58, 0x65};
    std::array<uint8_t, 42> hkdf{};
    ok = ok && hkdfSha256(ikm.data(), ikm.size(), hkdfSalt.data(),
                          hkdfSalt.size(), hkdfInfo.data(), hkdfInfo.size(),
                          hkdf.data(), hkdf.size()) &&
         constantTimeEqual(hkdf.data(), expectedHkdf.data(), hkdf.size());
    secureZero(ciphertext.data(), ciphertext.size());
    secureZero(tag.data(), tag.size());
    secureZero(decrypted.data(), decrypted.size());
    secureZero(pbkdf2.data(), pbkdf2.size());
    secureZero(ikm.data(), ikm.size());
    secureZero(hkdf.data(), hkdf.size());
    return ok;
}

}  // namespace vaultkey
