#pragma once

#include <cstddef>
#include <cstdint>

namespace vaultkey {

class Crypto {
  public:
    static constexpr std::size_t KEY_SIZE = 32;
    static constexpr std::size_t SALT_SIZE = 16;
    static constexpr std::size_t NONCE_SIZE = 12;
    static constexpr std::size_t TAG_SIZE = 16;

    static bool selfTest();
    static bool randomBytes(uint8_t* output, std::size_t length);
    static bool pbkdf2Sha256(const uint8_t* password,
                             std::size_t passwordLength, const uint8_t* salt,
                             std::size_t saltLength, uint32_t iterations,
                             uint8_t* output, std::size_t outputLength);
    static bool hkdfSha256(const uint8_t* inputKey,
                           std::size_t inputKeyLength, const uint8_t* salt,
                           std::size_t saltLength, const uint8_t* info,
                           std::size_t infoLength, uint8_t* output,
                           std::size_t outputLength);
    static bool aes256GcmEncrypt(const uint8_t key[KEY_SIZE],
                                 const uint8_t nonce[NONCE_SIZE],
                                 const uint8_t* aad, std::size_t aadLength,
                                 const uint8_t* plaintext,
                                 std::size_t plaintextLength,
                                 uint8_t* ciphertext,
                                 uint8_t tag[TAG_SIZE]);
    static bool aes256GcmDecrypt(const uint8_t key[KEY_SIZE],
                                 const uint8_t nonce[NONCE_SIZE],
                                 const uint8_t* aad, std::size_t aadLength,
                                 const uint8_t* ciphertext,
                                 std::size_t ciphertextLength,
                                 const uint8_t tag[TAG_SIZE],
                                 uint8_t* plaintext);
    static bool constantTimeEqual(const uint8_t* left, const uint8_t* right,
                                  std::size_t length);
};

}  // namespace vaultkey
