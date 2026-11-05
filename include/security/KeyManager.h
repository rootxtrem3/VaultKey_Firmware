#pragma once

#include <Preferences.h>

#include <cstdint>
#include <string>

#include "security/Crypto.h"
#include "security/SecureZero.h"

namespace vaultkey {

class KeyManager {
  public:
    bool begin();
    bool envelopePresent() const;
    bool provisioned() const;
    bool create(const std::string& pin, SecureBytes<Crypto::KEY_SIZE>& masterKey);
    bool unlock(const std::string& pin, SecureBytes<Crypto::KEY_SIZE>& masterKey);
    bool changePin(const uint8_t masterKey[Crypto::KEY_SIZE],
                   const std::string& newPin);
    bool markFactoryResetPending();
    bool factoryResetPending() const;
    bool destroy();

    uint16_t failedAttempts() const;
    uint64_t retryAfterUnix() const;
    bool setRetryState(uint16_t failures, uint64_t retryAfterUnix);
    bool clearRetryState();

    static bool validPin(const std::string& pin);

  private:
    struct __attribute__((packed)) KeyEnvelope {
        uint32_t magic;
        uint16_t version;
        uint16_t reserved;
        uint32_t iterations;
        uint8_t salt[Crypto::SALT_SIZE];
        uint8_t nonce[Crypto::NONCE_SIZE];
        uint8_t wrappedKey[Crypto::KEY_SIZE];
        uint8_t tag[Crypto::TAG_SIZE];
    };

    static constexpr uint32_t ENVELOPE_MAGIC = 0x564B4531U;  // VKE1
    static constexpr uint16_t ENVELOPE_VERSION = 1;
    static constexpr uint32_t MIN_ITERATIONS = 50000;
    static constexpr uint32_t MAX_ITERATIONS = 600000;
    static constexpr uint32_t TARGET_KDF_MS = 750;

    uint32_t benchmarkIterations(const std::string& pin,
                                 const uint8_t salt[Crypto::SALT_SIZE]);
    bool makeEnvelope(const uint8_t masterKey[Crypto::KEY_SIZE],
                      const std::string& pin, KeyEnvelope& envelope);
    bool storeEnvelope(const KeyEnvelope& envelope);
    bool loadEnvelope(KeyEnvelope& envelope) const;
    static bool validEnvelope(const KeyEnvelope& envelope);

    mutable Preferences preferences_;
    bool open_ = false;
};

}  // namespace vaultkey
