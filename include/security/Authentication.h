#pragma once

#include <cstdint>
#include <string>

#include "security/Crypto.h"
#include "security/KeyManager.h"
#include "security/SecureZero.h"

namespace vaultkey {

enum class AuthenticationState : uint8_t { Uninitialized, SetupRequired, Locked, Unlocked };

class Authentication {
  public:
    bool begin(KeyManager& keys, bool rtcValid, uint64_t rtcUnix,
               uint32_t nowMs);
    bool setup(const std::string& pin, const std::string& confirmation);
    bool unlock(const std::string& pin, bool rtcValid, uint64_t rtcUnix,
                uint32_t nowMs);
    bool reauthenticate(const std::string& pin);
    bool changePin(const std::string& currentPin, const std::string& newPin,
                   const std::string& confirmation);
    void lock();
    bool destroyKeys();

    AuthenticationState state() const { return state_; }
    bool unlocked() const { return state_ == AuthenticationState::Unlocked; }
    bool setupRequired() const {
        return state_ == AuthenticationState::SetupRequired;
    }
    const uint8_t* masterKey() const {
        return unlocked() ? masterKey_.data() : nullptr;
    }
    uint16_t failedAttempts() const;
    uint32_t retryDelayRemaining(bool rtcValid, uint64_t rtcUnix,
                                 uint32_t nowMs) const;

  private:
    static uint32_t delaySeconds(uint16_t failures);
    KeyManager* keys_ = nullptr;
    AuthenticationState state_ = AuthenticationState::Uninitialized;
    SecureBytes<Crypto::KEY_SIZE> masterKey_;
    uint32_t localRetryUntilMs_ = 0;
};

}  // namespace vaultkey
