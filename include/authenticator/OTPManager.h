#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "security/SecureStorage.h"
#include "vault/Models.h"

namespace vaultkey {

class OTPManager {
  public:
    explicit OTPManager(SecureStorage& storage) : storage_(storage) {}
    bool loadIndex();
    void clear();
    bool add(TotpEntry& entry);
    bool importUri(std::string uri, uint64_t createdAt, uint32_t& id,
                   std::string& error);
    bool update(const TotpEntry& entry);
    bool get(uint32_t id, TotpEntry& entry);
    bool remove(uint32_t id);
    bool code(uint32_t id, uint64_t unixTime, std::string& output,
              uint16_t& remainingSeconds);
    const std::vector<RecordSummary>& entries() const { return entries_; }
    std::size_t count() const { return entries_.size(); }

  private:
    uint32_t newId() const;
    bool exists(uint32_t id) const;
    SecureStorage& storage_;
    std::vector<RecordSummary> entries_;
};

}  // namespace vaultkey
