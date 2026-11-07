#include "vault/CredentialManager.h"

#include <algorithm>
#include <cctype>

#include "core/HardwareConfig.h"
#include "security/Crypto.h"
#include "security/SecureZero.h"
#include "vault/RecordCodec.h"

namespace vaultkey {
namespace {

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](char character) {
        return static_cast<char>(
            std::tolower(static_cast<unsigned char>(character)));
    });
    return value;
}

}  // namespace

bool CredentialManager::loadIndex() {
    clear();
    if (!storage_.unlocked()) return false;
    for (uint32_t id : storage_.listIds(RecordType::Credential)) {
        std::vector<uint8_t> plaintext;
        Credential record;
        const bool result = storage_.readRecord(RecordType::Credential, id,
                                                plaintext) &&
                            RecordCodec::decode(plaintext, record) &&
                            record.id == id;
        secureClear(plaintext);
        if (!result) {
            record.clearSensitive();
            clear();
            return false;
        }
        entries_.push_back(
            {record.id, RecordType::Credential, record.service, record.username});
        record.clearSensitive();
    }
    std::sort(entries_.begin(), entries_.end(), [](const auto& left,
                                                    const auto& right) {
        return lower(left.primary) < lower(right.primary);
    });
    return true;
}

void CredentialManager::clear() {
    for (RecordSummary& entry : entries_) {
        secureClear(entry.primary);
        secureClear(entry.secondary);
    }
    entries_.clear();
    entries_.shrink_to_fit();
}

bool CredentialManager::add(Credential& record) {
    if (!storage_.unlocked() || entries_.size() >= limits::MAX_CREDENTIALS) {
        return false;
    }
    if (record.id == 0) record.id = newId();
    if (record.id == 0 || exists(record.id) || !RecordCodec::validate(record)) {
        return false;
    }
    std::vector<uint8_t> plaintext;
    const bool result = RecordCodec::encode(record, plaintext) &&
                        storage_.writeRecord(RecordType::Credential, record.id,
                                             plaintext);
    secureClear(plaintext);
    return result && loadIndex();
}

bool CredentialManager::update(const Credential& record) {
    if (!exists(record.id) || !RecordCodec::validate(record)) return false;
    std::vector<uint8_t> plaintext;
    const bool result = RecordCodec::encode(record, plaintext) &&
                        storage_.writeRecord(RecordType::Credential, record.id,
                                             plaintext);
    secureClear(plaintext);
    return result && loadIndex();
}

bool CredentialManager::get(uint32_t id, Credential& record) {
    record.clearSensitive();
    record.service.clear();
    if (!exists(id)) return false;
    std::vector<uint8_t> plaintext;
    const bool result = storage_.readRecord(RecordType::Credential, id,
                                            plaintext) &&
                        RecordCodec::decode(plaintext, record) &&
                        record.id == id;
    secureClear(plaintext);
    if (!result) {
        record.clearSensitive();
        record.service.clear();
    }
    return result;
}

bool CredentialManager::remove(uint32_t id) {
    return exists(id) && storage_.deleteRecord(RecordType::Credential, id) &&
           loadIndex();
}

std::vector<RecordSummary> CredentialManager::search(
    const std::string& query) const {
    if (query.empty()) return entries_;
    const std::string needle = lower(query);
    std::vector<RecordSummary> matches;
    for (const auto& entry : entries_) {
        if (lower(entry.primary).find(needle) != std::string::npos ||
            lower(entry.secondary).find(needle) != std::string::npos) {
            matches.push_back(entry);
        }
    }
    return matches;
}

uint32_t CredentialManager::newId() const {
    for (int attempt = 0; attempt < 16; ++attempt) {
        uint32_t id = 0;
        if (!Crypto::randomBytes(reinterpret_cast<uint8_t*>(&id), sizeof(id))) {
            return 0;
        }
        if (id != 0 && !exists(id)) return id;
    }
    return 0;
}

bool CredentialManager::exists(uint32_t id) const {
    return std::any_of(entries_.begin(), entries_.end(),
                       [id](const RecordSummary& entry) { return entry.id == id; });
}

}  // namespace vaultkey
