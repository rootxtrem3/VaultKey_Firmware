#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "vault/Models.h"

namespace vaultkey {

class HOTP {
  public:
    static bool generate(const uint8_t* secret, std::size_t secretLength,
                         uint64_t counter, HashAlgorithm algorithm,
                         uint8_t digits, uint32_t& code);
    static bool generate(const std::vector<uint8_t>& secret, uint64_t counter,
                         HashAlgorithm algorithm, uint8_t digits,
                         uint32_t& code) {
        return generate(secret.data(), secret.size(), counter, algorithm,
                        digits, code);
    }
    static bool format(uint32_t code, uint8_t digits, std::string& output);
};

}  // namespace vaultkey
