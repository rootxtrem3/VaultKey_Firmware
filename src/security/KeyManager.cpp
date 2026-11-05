#include "security/KeyManager.h"

#include <Arduino.h>

#include <algorithm>
#include <cstddef>

namespace vaultkey {

bool KeyManager::begin() {
    open_ = preferences_.begin("vksec", false);
    return open_;
}

bool KeyManager::envelopePresent() const {
    return open_ && preferences_.isKey("envelope");
}

bool KeyManager::provisioned() const {
    if (!open_) return false;
    KeyEnvelope envelope{};
    const bool result = loadEnvelope(envelope);
    secureZero(&envelope, sizeof(envelope));
    return result;
}

bool KeyManager::validPin(const std::string& pin) {
    if (pin.size() < 6 || pin.size() > 12) return false;
    return std::all_of(pin.begin(), pin.end(),
                       [](char value) { return value >= '0' && value <= '9'; });
}

bool KeyManager::create(const std::string& pin,
                        SecureBytes<Crypto::KEY_SIZE>& masterKey) {
    masterKey.clear();
    if (!open_ || provisioned() || !validPin(pin) ||
        !Crypto::randomBytes(masterKey.data(), masterKey.size())) {
        masterKey.clear();
        return false;
    }
    KeyEnvelope envelope{};
    const bool result = makeEnvelope(masterKey.data(), pin, envelope) &&
                        storeEnvelope(envelope);
    secureZero(&envelope, sizeof(envelope));
    if (!result) {
        masterKey.clear();
        return false;
    }
    masterKey.markValid();
    clearRetryState();
    return true;
}

bool KeyManager::unlock(const std::string& pin,
                        SecureBytes<Crypto::KEY_SIZE>& masterKey) {
    masterKey.clear();
    if (!open_ || !validPin(pin)) return false;
    KeyEnvelope envelope{};
    if (!loadEnvelope(envelope)) {
        secureZero(&envelope, sizeof(envelope));
        return false;
    }
    SecureBytes<Crypto::KEY_SIZE> keyEncryptionKey;
    const bool derived = Crypto::pbkdf2Sha256(
        reinterpret_cast<const uint8_t*>(pin.data()), pin.size(), envelope.salt,
        sizeof(envelope.salt), envelope.iterations, keyEncryptionKey.data(),
        keyEncryptionKey.size());
    if (derived) keyEncryptionKey.markValid();
    const bool result =
        derived && Crypto::aes256GcmDecrypt(
                       keyEncryptionKey.data(), envelope.nonce,
                       reinterpret_cast<const uint8_t*>(&envelope),
                       offsetof(KeyEnvelope, wrappedKey), envelope.wrappedKey,
                       sizeof(envelope.wrappedKey), envelope.tag,
                       masterKey.data());
    secureZero(&envelope, sizeof(envelope));
    if (!result) {
        masterKey.clear();
        return false;
    }
    masterKey.markValid();
    return true;
}

bool KeyManager::changePin(const uint8_t masterKey[Crypto::KEY_SIZE],
                           const std::string& newPin) {
    if (!open_ || masterKey == nullptr || !validPin(newPin)) return false;
    KeyEnvelope envelope{};
    const bool result = makeEnvelope(masterKey, newPin, envelope) &&
                        storeEnvelope(envelope);
    secureZero(&envelope, sizeof(envelope));
    return result;
}

bool KeyManager::markFactoryResetPending() {
    return open_ &&
           preferences_.putBool("wipe_pending", true) == sizeof(uint8_t) &&
           preferences_.getBool("wipe_pending", false);
}

bool KeyManager::factoryResetPending() const {
    return open_ && preferences_.getBool("wipe_pending", false);
}

bool KeyManager::destroy() {
    if (!open_) return false;
    bool result = true;
    if (preferences_.isKey("envelope")) result &= preferences_.remove("envelope");
    if (preferences_.isKey("pending")) result &= preferences_.remove("pending");
    result &= clearRetryState();
    // The journal marker is the final commit. Leave it set if any earlier
    // deletion failed so startup retries the authorized wipe.
    if (result && preferences_.isKey("wipe_pending"))
        result = preferences_.remove("wipe_pending");
    return result;
}

uint16_t KeyManager::failedAttempts() const {
    return open_ ? preferences_.getUShort("failures", 0) : 0;
}

uint64_t KeyManager::retryAfterUnix() const {
    return open_ ? preferences_.getULong64("retry_at", 0) : 0;
}

bool KeyManager::setRetryState(uint16_t failures, uint64_t retryAfterUnix) {
    return open_ &&
           preferences_.putUShort("failures", failures) == sizeof(uint16_t) &&
           preferences_.putULong64("retry_at", retryAfterUnix) ==
               sizeof(uint64_t);
}

bool KeyManager::clearRetryState() {
    if (!open_) return false;
    bool result = true;
    if (preferences_.isKey("failures")) result &= preferences_.remove("failures");
    if (preferences_.isKey("retry_at")) result &= preferences_.remove("retry_at");
    return result;
}

uint32_t KeyManager::benchmarkIterations(
    const std::string& pin, const uint8_t salt[Crypto::SALT_SIZE]) {
    static constexpr uint32_t PROBE_ITERATIONS = 2000;
    SecureBytes<Crypto::KEY_SIZE> probe;
    const uint32_t started = millis();
    if (!Crypto::pbkdf2Sha256(
            reinterpret_cast<const uint8_t*>(pin.data()), pin.size(), salt,
            Crypto::SALT_SIZE, PROBE_ITERATIONS, probe.data(), probe.size())) {
        return 0;
    }
    const uint32_t elapsed = std::max<uint32_t>(1, millis() - started);
    uint64_t estimate = static_cast<uint64_t>(PROBE_ITERATIONS) * TARGET_KDF_MS /
                        elapsed;
    estimate = std::max<uint64_t>(MIN_ITERATIONS, estimate);
    estimate = std::min<uint64_t>(MAX_ITERATIONS, estimate);
    return static_cast<uint32_t>(estimate);
}

bool KeyManager::makeEnvelope(const uint8_t masterKey[Crypto::KEY_SIZE],
                              const std::string& pin, KeyEnvelope& envelope) {
    secureZero(&envelope, sizeof(envelope));
    envelope.magic = ENVELOPE_MAGIC;
    envelope.version = ENVELOPE_VERSION;
    if (!Crypto::randomBytes(envelope.salt, sizeof(envelope.salt)) ||
        !Crypto::randomBytes(envelope.nonce, sizeof(envelope.nonce))) {
        return false;
    }
    envelope.iterations = benchmarkIterations(pin, envelope.salt);
    if (envelope.iterations == 0) return false;

    SecureBytes<Crypto::KEY_SIZE> keyEncryptionKey;
    if (!Crypto::pbkdf2Sha256(
            reinterpret_cast<const uint8_t*>(pin.data()), pin.size(),
            envelope.salt, sizeof(envelope.salt), envelope.iterations,
            keyEncryptionKey.data(), keyEncryptionKey.size())) {
        return false;
    }
    keyEncryptionKey.markValid();
    return Crypto::aes256GcmEncrypt(
        keyEncryptionKey.data(), envelope.nonce,
        reinterpret_cast<const uint8_t*>(&envelope),
        offsetof(KeyEnvelope, wrappedKey), masterKey, Crypto::KEY_SIZE,
        envelope.wrappedKey, envelope.tag);
}

bool KeyManager::storeEnvelope(const KeyEnvelope& envelope) {
    if (!open_ || !validEnvelope(envelope)) return false;
    if (preferences_.putBytes("pending", &envelope, sizeof(envelope)) !=
        sizeof(envelope)) {
        return false;
    }
    KeyEnvelope verification{};
    const bool pendingValid =
        preferences_.getBytes("pending", &verification, sizeof(verification)) ==
            sizeof(verification) &&
        Crypto::constantTimeEqual(
            reinterpret_cast<const uint8_t*>(&verification),
            reinterpret_cast<const uint8_t*>(&envelope), sizeof(envelope));
    secureZero(&verification, sizeof(verification));
    if (!pendingValid) return false;
    if (preferences_.putBytes("envelope", &envelope, sizeof(envelope)) !=
        sizeof(envelope)) {
        return false;
    }
    const bool finalValid =
        preferences_.getBytes("envelope", &verification, sizeof(verification)) ==
            sizeof(verification) &&
        Crypto::constantTimeEqual(
            reinterpret_cast<const uint8_t*>(&verification),
            reinterpret_cast<const uint8_t*>(&envelope), sizeof(envelope));
    secureZero(&verification, sizeof(verification));
    if (!finalValid) return false;
    preferences_.remove("pending");
    return true;
}

bool KeyManager::loadEnvelope(KeyEnvelope& envelope) const {
    secureZero(&envelope, sizeof(envelope));
    return open_ &&
           preferences_.getBytesLength("envelope") == sizeof(envelope) &&
           preferences_.getBytes("envelope", &envelope, sizeof(envelope)) ==
               sizeof(envelope) &&
           validEnvelope(envelope);
}

bool KeyManager::validEnvelope(const KeyEnvelope& envelope) {
    return envelope.magic == ENVELOPE_MAGIC &&
           envelope.version == ENVELOPE_VERSION &&
           envelope.iterations >= MIN_ITERATIONS &&
           envelope.iterations <= MAX_ITERATIONS;
}

}  // namespace vaultkey
