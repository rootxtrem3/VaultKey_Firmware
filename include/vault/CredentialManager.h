#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "security/SecureStorage.h"
#include "vault/Models.h"

namespace vaultkey {

class CredentialManager {
  public:
    explicit CredentialManager(SecureStorage& storage) : storage_(storage) {}
    bool loadIndex();
    void clear();
    bool add(Credential& record);
    bool update(const Credential& record);
    bool get(uint32_t id, Credential& record);
    bool remove(uint32_t id);
    const std::vector<RecordSummary>& entries() const { return entries_; }
    std::vector<RecordSummary> search(const std::string& query) const;
    std::size_t count() const { return entries_.size(); }

  private:
    uint32_t newId() const;
    bool exists(uint32_t id) const;
    SecureStorage& storage_;
    std::vector<RecordSummary> entries_;
};

}  // namespace vaultkey
