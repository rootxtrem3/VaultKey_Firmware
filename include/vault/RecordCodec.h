#pragma once

#include <cstdint>
#include <vector>

#include "vault/Models.h"

namespace vaultkey {

class RecordCodec {
  public:
    static constexpr uint8_t VERSION = 1;

    static bool validate(const Credential& record);
    static bool validate(const TotpEntry& record);
    static bool encode(const Credential& record, std::vector<uint8_t>& output);
    static bool decode(const std::vector<uint8_t>& input, Credential& record);
    static bool encode(const TotpEntry& record, std::vector<uint8_t>& output);
    static bool decode(const std::vector<uint8_t>& input, TotpEntry& record);
};

}  // namespace vaultkey
