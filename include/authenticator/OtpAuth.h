#pragma once

#include <string>

#include "vault/Models.h"

namespace vaultkey {

class OtpAuth {
  public:
    // Parses only otpauth://totp URIs. On failure, error contains a non-secret
    // diagnostic suitable for a protocol response.
    static bool parse(const std::string& uri, TotpEntry& entry,
                      std::string& error);
};

}  // namespace vaultkey
