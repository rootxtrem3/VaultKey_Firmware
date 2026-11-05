#include "security/Authentication.h"

#include <algorithm>

namespace vaultkey {

bool Authentication::begin(KeyManager& keys, bool rtcValid, uint64_t rtcUnix,
                           uint32_t nowMs) {
    keys_ = &keys;
    state_ = keys.provisioned() ? AuthenticationState::Locked
                                : AuthenticationState::SetupRequired;
    const uint16_t failures = keys.failedAttempts();
    if (failures != 0) {
        const uint32_t seconds = delaySeconds(failures);
        localRetryUntilMs_ = nowMs + seconds * 1000U;
        if (rtcValid && keys.retryAfterUnix() != 0 &&
            keys.retryAfterUnix() <= rtcUnix) {
            localRetryUntilMs_ = nowMs;
        }
    }
    return true;
}

bool Authentication::setup(const std::string& pin,
                           const std::string& confirmation) {
    if (keys_ == nullptr || state_ != AuthenticationState::SetupRequired ||
        pin != confirmation || !KeyManager::validPin(pin) ||
        !keys_->create(pin, masterKey_)) {
        return false;
    }
    state_ = AuthenticationState::Unlocked;
    return true;
}

bool Authentication::unlock(const std::string& pin, bool rtcValid,
                            uint64_t rtcUnix, uint32_t nowMs) {
    if (keys_ == nullptr || state_ != AuthenticationState::Locked ||
        retryDelayRemaining(rtcValid, rtcUnix, nowMs) != 0) {
        return false;
    }
    if (keys_->unlock(pin, masterKey_)) {
        keys_->clearRetryState();
        localRetryUntilMs_ = 0;
        state_ = AuthenticationState::Unlocked;
        return true;
    }
    const uint16_t failures =
        std::min<uint16_t>(static_cast<uint16_t>(keys_->failedAttempts() + 1U),
                           1000U);
    const uint32_t seconds = delaySeconds(failures);
    localRetryUntilMs_ = nowMs + seconds * 1000U;
    keys_->setRetryState(failures, rtcValid ? rtcUnix + seconds : 0);
    return false;
}

bool Authentication::reauthenticate(const std::string& pin) {
    if (!unlocked() || keys_ == nullptr) return false;
    SecureBytes<Crypto::KEY_SIZE> verification;
    if (!keys_->unlock(pin, verification)) return false;
    return Crypto::constantTimeEqual(masterKey_.data(), verification.data(),
                                     masterKey_.size());
}

bool Authentication::changePin(const std::string& currentPin,
                               const std::string& newPin,
                               const std::string& confirmation) {
    return unlocked() && newPin == confirmation &&
           KeyManager::validPin(newPin) && reauthenticate(currentPin) &&
           keys_->changePin(masterKey_.data(), newPin);
}

void Authentication::lock() {
    masterKey_.clear();
    if (state_ == AuthenticationState::Unlocked) {
        state_ = AuthenticationState::Locked;
    }
}

bool Authentication::destroyKeys() {
    masterKey_.clear();
    if (keys_ == nullptr || !keys_->destroy()) return false;
    state_ = AuthenticationState::SetupRequired;
    return true;
}

uint16_t Authentication::failedAttempts() const {
    return keys_ == nullptr ? 0 : keys_->failedAttempts();
}

uint32_t Authentication::retryDelayRemaining(bool rtcValid, uint64_t rtcUnix,
                                             uint32_t nowMs) const {
    uint32_t remainingMs =
        static_cast<int32_t>(localRetryUntilMs_ - nowMs) > 0
            ? localRetryUntilMs_ - nowMs
            : 0;
    if (rtcValid && keys_ != nullptr && keys_->retryAfterUnix() > rtcUnix) {
        const uint64_t seconds = keys_->retryAfterUnix() - rtcUnix;
        remainingMs = std::max<uint32_t>(
            remainingMs,
            static_cast<uint32_t>(std::min<uint64_t>(seconds, 300U) * 1000U));
    }
    return (remainingMs + 999U) / 1000U;
}

uint32_t Authentication::delaySeconds(uint16_t failures) {
    if (failures == 0) return 0;
    const uint16_t exponent = std::min<uint16_t>(failures - 1U, 8U);
    return std::min<uint32_t>(1U << exponent, 300U);
}

}  // namespace vaultkey
