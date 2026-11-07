#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "security/SecureZero.h"

namespace vaultkey {

enum class HashAlgorithm : uint8_t { Sha1 = 1, Sha256 = 2, Sha512 = 3 };
enum class RecordType : uint8_t { Credential = 1, Totp = 2, Metadata = 3 };

struct Credential {
    uint32_t id = 0;
    std::string service;
    std::string username;
    std::string password;
    std::string url;
    std::string notes;
    uint64_t createdAt = 0;

    void clearSensitive() {
        secureClear(username);
        secureClear(password);
        secureClear(url);
        secureClear(notes);
    }
};

struct TotpEntry {
    uint32_t id = 0;
    std::string issuer;
    std::string account;
    std::vector<uint8_t> secret;
    HashAlgorithm algorithm = HashAlgorithm::Sha1;
    uint8_t digits = 6;
    uint16_t period = 30;
    uint64_t createdAt = 0;

    void clearSensitive() { secureClear(secret); }
};

struct RecordSummary {
    uint32_t id = 0;
    RecordType type = RecordType::Credential;
    std::string primary;
    std::string secondary;
};

}  // namespace vaultkey
