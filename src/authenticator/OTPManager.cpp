#include "authenticator/OTPManager.h"

#include <algorithm>
#include <cctype>

#include "authenticator/OtpAuth.h"
#include "authenticator/TOTP.h"
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

bool OTPManager::loadIndex() {
    clear();
    if (!storage_.unlocked()) return false;
    for (uint32_t id : storage_.listIds(RecordType::Totp)) {
        std::vector<uint8_t> plaintext;
        TotpEntry entry;
        const bool result = storage_.readRecord(RecordType::Totp, id, plaintext) &&
                            RecordCodec::decode(plaintext, entry) &&
                            entry.id == id;
        secureClear(plaintext);
        if (!result) {
            entry.clearSensitive();
            clear();
            return false;
        }
        entries_.push_back(
            {entry.id, RecordType::Totp, entry.issuer, entry.account});
        entry.clearSensitive();
    }
    std::sort(entries_.begin(), entries_.end(), [](const auto& left,
                                                    const auto& right) {
        const std::string leftKey = lower(left.primary + "\n" + left.secondary);
        const std::string rightKey = lower(right.primary + "\n" + right.secondary);
        return leftKey < rightKey;
    });
    return true;
}

void OTPManager::clear() {
    for (RecordSummary& entry : entries_) {
        secureClear(entry.primary);
        secureClear(entry.secondary);
    }
    entries_.clear();
    entries_.shrink_to_fit();
}

bool OTPManager::add(TotpEntry& entry) {
    if (!storage_.unlocked() || entries_.size() >= limits::MAX_TOTP_ENTRIES) {
        return false;
    }
    if (entry.id == 0) entry.id = newId();
    if (entry.id == 0 || exists(entry.id) || !RecordCodec::validate(entry)) {
        return false;
    }
    std::vector<uint8_t> plaintext;
    const bool result = RecordCodec::encode(entry, plaintext) &&
                        storage_.writeRecord(RecordType::Totp, entry.id,
                                             plaintext);
    secureClear(plaintext);
    return result && loadIndex();
}

bool OTPManager::importUri(std::string uri, uint64_t createdAt,
                           uint32_t& id, std::string& error) {
    id = 0;
    TotpEntry entry;
    if (!OtpAuth::parse(uri, entry, error)) {
        secureClear(uri);
        return false;
    }
    entry.createdAt = createdAt;
    const bool result = add(entry);
    id = result ? entry.id : 0;
    entry.clearSensitive();
    secureClear(uri);
    if (!result && error.empty()) error = "storage_failed";
    return result;
}

bool OTPManager::update(const TotpEntry& entry) {
    if (!exists(entry.id) || !RecordCodec::validate(entry)) return false;
    std::vector<uint8_t> plaintext;
    const bool result = RecordCodec::encode(entry, plaintext) &&
                        storage_.writeRecord(RecordType::Totp, entry.id,
                                             plaintext);
    secureClear(plaintext);
    return result && loadIndex();
}

bool OTPManager::get(uint32_t id, TotpEntry& entry) {
    entry.clearSensitive();
    entry.issuer.clear();
    entry.account.clear();
    if (!exists(id)) return false;
    std::vector<uint8_t> plaintext;
    const bool result = storage_.readRecord(RecordType::Totp, id, plaintext) &&
                        RecordCodec::decode(plaintext, entry) && entry.id == id;
    secureClear(plaintext);
    if (!result) {
        entry.clearSensitive();
        entry.issuer.clear();
        entry.account.clear();
    }
    return result;
}

bool OTPManager::remove(uint32_t id) {
    return exists(id) && storage_.deleteRecord(RecordType::Totp, id) &&
           loadIndex();
}

bool OTPManager::code(uint32_t id, uint64_t unixTime, std::string& output,
                      uint16_t& remainingSeconds) {
    TotpEntry entry;
    if (!get(id, entry)) return false;
    const bool result = TOTP::generate(entry, unixTime, output);
    remainingSeconds = result ? TOTP::remaining(unixTime, entry.period) : 0;
    entry.clearSensitive();
    return result;
}

uint32_t OTPManager::newId() const {
    for (int attempt = 0; attempt < 16; ++attempt) {
        uint32_t id = 0;
        if (!Crypto::randomBytes(reinterpret_cast<uint8_t*>(&id), sizeof(id))) {
            return 0;
        }
        if (id != 0 && !exists(id)) return id;
    }
    return 0;
}

bool OTPManager::exists(uint32_t id) const {
    return std::any_of(entries_.begin(), entries_.end(),
                       [id](const RecordSummary& entry) { return entry.id == id; });
}

}  // namespace vaultkey
