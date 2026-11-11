#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "vault/Models.h"

namespace vaultkey {

class Base32 {
  public:
    static bool decode(const std::string& input, std::vector<uint8_t>& output);
};

class TOTP {
  public:
    static bool selfTest();
    static bool generate(const uint8_t* secret, std::size_t secretLength,
                         uint64_t unixTime, HashAlgorithm algorithm,
                         uint8_t digits, uint16_t period, std::string& output);
    static bool generate(const TotpEntry& entry, uint64_t unixTime,
                         std::string& output) {
        return generate(entry.secret.data(), entry.secret.size(), unixTime,
                        entry.algorithm, entry.digits, entry.period, output);
    }
    static uint16_t remaining(uint64_t unixTime, uint16_t period);
};

}  // namespace vaultkey
