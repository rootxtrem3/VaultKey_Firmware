#include "security/SecureStorage.h"

#include <LittleFS.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "core/HardwareConfig.h"

namespace vaultkey {
namespace {

constexpr const char* ROOT = "/vault";
constexpr const char* MANIFEST = "/vault/manifest.vkm";
constexpr uint8_t STORAGE_SALT[] = "VaultKey storage rev-D v1";
constexpr uint8_t CREDENTIAL_INFO[] = "credential-record-key";
constexpr uint8_t TOTP_INFO[] = "totp-record-key";
constexpr uint8_t METADATA_INFO[] = "manifest-key";

void putU16(uint8_t* output, uint16_t value) {
    output[0] = static_cast<uint8_t>(value >> 8U);
    output[1] = static_cast<uint8_t>(value);
}

void putU32(uint8_t* output, uint32_t value) {
    output[0] = static_cast<uint8_t>(value >> 24U);
    output[1] = static_cast<uint8_t>(value >> 16U);
    output[2] = static_cast<uint8_t>(value >> 8U);
    output[3] = static_cast<uint8_t>(value);
}

uint16_t getU16(const uint8_t* input) {
    return static_cast<uint16_t>(input[0]) << 8U | input[1];
}

uint32_t getU32(const uint8_t* input) {
    return static_cast<uint32_t>(input[0]) << 24U |
           static_cast<uint32_t>(input[1]) << 16U |
           static_cast<uint32_t>(input[2]) << 8U | input[3];
}

bool endsWith(const std::string& value, const char* suffix) {
    const std::size_t length = std::strlen(suffix);
    return value.size() >= length &&
           value.compare(value.size() - length, length, suffix) == 0;
}

std::string fullName(File& file) {
    const char* name = file.name();
    if (name == nullptr) return {};
    std::string result(name);
    if (!result.empty() && result.front() != '/') result = std::string(ROOT) + "/" + result;
    return result;
}

}  // namespace

bool SecureStorage::begin(bool allowFormat) {
    mounted_ = LittleFS.begin(false);
    if (!mounted_ && allowFormat) {
        if (!LittleFS.format()) {
            status_ = StorageStatus::FormatFailed;
            return false;
        }
        mounted_ = LittleFS.begin(false);
    }
    if (!mounted_) {
        status_ = StorageStatus::MountFailed;
        return false;
    }
    if (!LittleFS.exists(ROOT) && !LittleFS.mkdir(ROOT)) {
        status_ = StorageStatus::IoError;
        return false;
    }
    if (!recoverTransactions()) {
        status_ = StorageStatus::IoError;
        return false;
    }
    status_ = StorageStatus::Locked;
    return true;
}

bool SecureStorage::unlock(const uint8_t masterKey[Crypto::KEY_SIZE]) {
    lock();
    if (!mounted_ || masterKey == nullptr) {
        status_ = mounted_ ? StorageStatus::Locked : StorageStatus::NotInitialized;
        return false;
    }
    const auto derive = [&](const uint8_t* info, std::size_t infoLength,
                            SecureBytes<Crypto::KEY_SIZE>& output) {
        const bool result = Crypto::hkdfSha256(
            masterKey, Crypto::KEY_SIZE, STORAGE_SALT, sizeof(STORAGE_SALT) - 1,
            info, infoLength, output.data(), output.size());
        if (result) output.markValid();
        return result;
    };
    if (!derive(CREDENTIAL_INFO, sizeof(CREDENTIAL_INFO) - 1, credentialKey_) ||
        !derive(TOTP_INFO, sizeof(TOTP_INFO) - 1, totpKey_) ||
        !derive(METADATA_INFO, sizeof(METADATA_INFO) - 1, metadataKey_)) {
        lock();
        status_ = StorageStatus::IoError;
        return false;
    }
    unlocked_ = true;
    if (!LittleFS.exists(MANIFEST)) {
        // An absent manifest is valid only for an entirely new, empty store.
        File root = LittleFS.open(ROOT);
        bool hasRecords = false;
        if (root && root.isDirectory()) {
            File file = root.openNextFile();
            while (file) {
                const std::string name = fullName(file);
                if (endsWith(name, ".vkr")) hasRecords = true;
                file = root.openNextFile();
            }
        }
        if (hasRecords || !initializeManifest()) {
            status_ = StorageStatus::ManifestCorrupt;
            lock();
            status_ = StorageStatus::ManifestCorrupt;
            return false;
        }
    } else if (!loadManifest()) {
        status_ = StorageStatus::ManifestCorrupt;
        lock();
        status_ = StorageStatus::ManifestCorrupt;
        return false;
    }
    if (!verifyManifestRecords()) {
        status_ = StorageStatus::RecordCorrupt;
        lock();
        status_ = StorageStatus::RecordCorrupt;
        return false;
    }
    status_ = StorageStatus::Ready;
    return true;
}

void SecureStorage::lock() {
    credentialKey_.clear();
    totpKey_.clear();
    metadataKey_.clear();
    credentialIds_.clear();
    totpIds_.clear();
    manifestGeneration_ = 0;
    unlocked_ = false;
    if (mounted_ && status_ == StorageStatus::Ready) status_ = StorageStatus::Locked;
}

bool SecureStorage::writeRecord(RecordType type, uint32_t id,
                                const std::vector<uint8_t>& plaintext) {
    if (!unlocked_ || !healthy() || !validType(type) || id == 0 ||
        plaintext.empty() || plaintext.size() > limits::RECORD_PLAINTEXT) {
        return false;
    }
    const bool existing = contains(type, id);
    const std::string destination = pathFor(type, id);
    if (!sealToPath(destination + ".tmp", type, id, plaintext, keyFor(type)) ||
        !atomicReplace(destination + ".tmp", destination)) {
        status_ = StorageStatus::IoError;
        return false;
    }
    if (!existing) {
        auto& list = ids(type);
        if (list.size() >= (type == RecordType::Credential
                                ? limits::MAX_CREDENTIALS
                                : limits::MAX_TOTP_ENTRIES)) {
            LittleFS.remove(destination.c_str());
            return false;
        }
        list.push_back(id);
        std::sort(list.begin(), list.end());
        if (!saveManifest()) {
            list.erase(std::remove(list.begin(), list.end(), id), list.end());
            LittleFS.remove(destination.c_str());
            status_ = StorageStatus::IoError;
            return false;
        }
    }
    return true;
}

bool SecureStorage::readRecord(RecordType type, uint32_t id,
                               std::vector<uint8_t>& plaintext) {
    plaintext.clear();
    if (!unlocked_ || !healthy() || !contains(type, id)) return false;
    if (!unsealFromPath(pathFor(type, id), type, id, plaintext, keyFor(type))) {
        secureClear(plaintext);
        status_ = StorageStatus::RecordCorrupt;
        return false;
    }
    return true;
}

bool SecureStorage::deleteRecord(RecordType type, uint32_t id) {
    if (!unlocked_ || !healthy() || !contains(type, id)) return false;
    auto& list = ids(type);
    const auto oldList = list;
    list.erase(std::remove(list.begin(), list.end(), id), list.end());
    if (!saveManifest()) {
        list = oldList;
        status_ = StorageStatus::IoError;
        return false;
    }
    const std::string path = pathFor(type, id);
    if (!LittleFS.exists(path.c_str())) return true;
    const std::string deleted = path + ".del";
    LittleFS.remove(deleted.c_str());
    if (!LittleFS.rename(path.c_str(), deleted.c_str())) {
        status_ = StorageStatus::IoError;
        return false;
    }
    if (!LittleFS.remove(deleted.c_str())) {
        status_ = StorageStatus::IoError;
        return false;
    }
    return true;
}

std::vector<uint32_t> SecureStorage::listIds(RecordType type) const {
    if (!unlocked_ || !validType(type)) return {};
    return ids(type);
}

bool SecureStorage::wipe() {
    if (!mounted_) return false;
    std::vector<std::string> files;
    File root = LittleFS.open(ROOT);
    if (root && root.isDirectory()) {
        File file = root.openNextFile();
        while (file) {
            files.push_back(fullName(file));
            file = root.openNextFile();
        }
    }
    root.close();
    bool result = true;
    for (const std::string& path : files) {
        result &= LittleFS.remove(path.c_str());
    }
    if (!result) {
        // Factory wipe is already explicitly authorized. If individual file
        // deletion fails, format the data partition so stale ciphertext does
        // not block the next first-boot setup.
        LittleFS.end();
        mounted_ = false;
        result = LittleFS.format() && LittleFS.begin(false);
        mounted_ = result;
        if (result && !LittleFS.exists(ROOT)) result = LittleFS.mkdir(ROOT);
    }
    credentialIds_.clear();
    totpIds_.clear();
    manifestGeneration_ = 0;
    lock();
    status_ = result ? StorageStatus::Locked : StorageStatus::IoError;
    return result;
}

const char* SecureStorage::statusText() const {
    switch (status_) {
        case StorageStatus::NotInitialized: return "not initialized";
        case StorageStatus::Ready: return "ready";
        case StorageStatus::MountFailed: return "mount failed";
        case StorageStatus::FormatFailed: return "format failed";
        case StorageStatus::ManifestCorrupt: return "manifest corrupt";
        case StorageStatus::RecordCorrupt: return "record corrupt";
        case StorageStatus::IoError: return "I/O error";
        case StorageStatus::Locked: return "locked";
    }
    return "unknown";
}

bool SecureStorage::recoverTransactions() {
    File root = LittleFS.open(ROOT);
    if (!root || !root.isDirectory()) return false;
    std::vector<std::string> names;
    File file = root.openNextFile();
    while (file) {
        names.push_back(fullName(file));
        file = root.openNextFile();
    }
    for (const std::string& name : names) {
        if (endsWith(name, ".tmp") || endsWith(name, ".del")) {
            if (!LittleFS.remove(name.c_str())) return false;
        } else if (endsWith(name, ".bak")) {
            const std::string target = name.substr(0, name.size() - 4);
            if (LittleFS.exists(target.c_str())) {
                if (!LittleFS.remove(name.c_str())) return false;
            } else if (!LittleFS.rename(name.c_str(), target.c_str())) {
                return false;
            }
        }
    }
    return true;
}

bool SecureStorage::initializeManifest() {
    credentialIds_.clear();
    totpIds_.clear();
    manifestGeneration_ = 0;
    return saveManifest();
}

bool SecureStorage::loadManifest() {
    std::vector<uint8_t> plaintext;
    if (!unsealFromPath(MANIFEST, RecordType::Metadata, 0, plaintext,
                        metadataKey_.data()) ||
        plaintext.size() < 16 || getU32(plaintext.data()) != MANIFEST_MAGIC ||
        plaintext[4] != 1) {
        secureClear(plaintext);
        return false;
    }
    std::size_t position = 8;
    manifestGeneration_ = getU32(plaintext.data() + position);
    position += 4;
    if (position + 2 > plaintext.size()) {
        secureClear(plaintext);
        return false;
    }
    const uint16_t credentials = getU16(plaintext.data() + position);
    position += 2;
    if (credentials > limits::MAX_CREDENTIALS ||
        position + static_cast<std::size_t>(credentials) * 4U + 2U >
            plaintext.size()) {
        secureClear(plaintext);
        return false;
    }
    credentialIds_.clear();
    for (uint16_t index = 0; index < credentials; ++index, position += 4) {
        credentialIds_.push_back(getU32(plaintext.data() + position));
    }
    const uint16_t totps = getU16(plaintext.data() + position);
    position += 2;
    if (totps > limits::MAX_TOTP_ENTRIES ||
        position + static_cast<std::size_t>(totps) * 4U != plaintext.size()) {
        secureClear(plaintext);
        return false;
    }
    totpIds_.clear();
    for (uint16_t index = 0; index < totps; ++index, position += 4) {
        totpIds_.push_back(getU32(plaintext.data() + position));
    }
    secureClear(plaintext);
    auto validIds = [](std::vector<uint32_t>& values) {
        std::sort(values.begin(), values.end());
        return std::none_of(values.begin(), values.end(),
                            [](uint32_t id) { return id == 0; }) &&
               std::adjacent_find(values.begin(), values.end()) == values.end();
    };
    return validIds(credentialIds_) && validIds(totpIds_);
}

bool SecureStorage::saveManifest() {
    if (!unlocked_) return false;
    std::vector<uint8_t> plaintext;
    plaintext.resize(16 + credentialIds_.size() * 4U + totpIds_.size() * 4U);
    putU32(plaintext.data(), MANIFEST_MAGIC);
    plaintext[4] = 1;
    plaintext[5] = plaintext[6] = plaintext[7] = 0;
    putU32(plaintext.data() + 8, ++manifestGeneration_);
    std::size_t position = 12;
    putU16(plaintext.data() + position,
           static_cast<uint16_t>(credentialIds_.size()));
    position += 2;
    for (uint32_t id : credentialIds_) {
        putU32(plaintext.data() + position, id);
        position += 4;
    }
    // Insert TOTP count before TOTP IDs; resize above includes its 2 bytes via 14.
    putU16(plaintext.data() + position, static_cast<uint16_t>(totpIds_.size()));
    position += 2;
    for (uint32_t id : totpIds_) {
        putU32(plaintext.data() + position, id);
        position += 4;
    }
    const bool result = sealToPath(std::string(MANIFEST) + ".tmp",
                                   RecordType::Metadata, 0, plaintext,
                                   metadataKey_.data()) &&
                        atomicReplace(std::string(MANIFEST) + ".tmp", MANIFEST);
    secureClear(plaintext);
    return result;
}

bool SecureStorage::verifyManifestRecords() {
    std::vector<uint8_t> plaintext;
    for (uint32_t id : credentialIds_) {
        if (!unsealFromPath(pathFor(RecordType::Credential, id),
                            RecordType::Credential, id, plaintext,
                            credentialKey_.data())) {
            secureClear(plaintext);
            return false;
        }
        secureClear(plaintext);
    }
    for (uint32_t id : totpIds_) {
        if (!unsealFromPath(pathFor(RecordType::Totp, id), RecordType::Totp, id,
                            plaintext, totpKey_.data())) {
            secureClear(plaintext);
            return false;
        }
        secureClear(plaintext);
    }

    // Remove authenticated but uncommitted records left by a power loss before
    // their manifest update. Unknown/corrupt filenames are retained and fail
    // closed rather than being silently accepted.
    File root = LittleFS.open(ROOT);
    if (!root || !root.isDirectory()) return false;
    File file = root.openNextFile();
    while (file) {
        const std::string name = fullName(file);
        file = root.openNextFile();
        const std::size_t slash = name.find_last_of('/');
        const std::string base = name.substr(slash == std::string::npos ? 0 : slash + 1);
        if (base == "manifest.vkm") continue;
        if (base.size() == 14 && (base[0] == 'c' || base[0] == 't') &&
            base[1] == '_' && base.substr(10) == ".vkr") {
            const std::string hex = base.substr(2, 8);
            if (!std::all_of(hex.begin(), hex.end(), [](char character) {
                    return (character >= '0' && character <= '9') ||
                           (character >= 'A' && character <= 'F');
                })) {
                return false;
            }
            const uint32_t id = static_cast<uint32_t>(
                std::strtoul(hex.c_str(), nullptr, 16));
            const RecordType type = base[0] == 'c' ? RecordType::Credential
                                                   : RecordType::Totp;
            if (id != 0 && !contains(type, id) && !LittleFS.remove(name.c_str())) {
                return false;
            }
        } else {
            return false;
        }
    }
    return true;
}

bool SecureStorage::sealToPath(const std::string& path, RecordType type,
                               uint32_t id,
                               const std::vector<uint8_t>& plaintext,
                               const uint8_t key[Crypto::KEY_SIZE]) {
    if (key == nullptr || plaintext.empty() || plaintext.size() > 0xFFFFU) {
        return false;
    }
    std::array<uint8_t, HEADER_SIZE> header{};
    header[0] = 'V';
    header[1] = 'K';
    header[2] = 'R';
    header[3] = '1';
    header[4] = FILE_SCHEMA;
    header[5] = static_cast<uint8_t>(type);
    putU32(header.data() + 6, id);
    putU16(header.data() + 10, static_cast<uint16_t>(plaintext.size()));
    if (!Crypto::randomBytes(header.data() + 12, Crypto::NONCE_SIZE)) return false;
    std::vector<uint8_t> ciphertext(plaintext.size());
    if (!Crypto::aes256GcmEncrypt(
            key, header.data() + 12, header.data(), AAD_SIZE, plaintext.data(),
            plaintext.size(), ciphertext.data(), header.data() + AAD_SIZE)) {
        secureClear(ciphertext);
        return false;
    }
    LittleFS.remove(path.c_str());
    File file = LittleFS.open(path.c_str(), FILE_WRITE);
    const bool result = file &&
                        file.write(header.data(), header.size()) == header.size() &&
                        file.write(ciphertext.data(), ciphertext.size()) ==
                            ciphertext.size();
    if (file) {
        file.flush();
        file.close();
    }
    secureClear(ciphertext);
    if (!result) {
        LittleFS.remove(path.c_str());
        return false;
    }
    std::vector<uint8_t> verification;
    const bool verified = unsealFromPath(path, type, id, verification, key) &&
                          verification.size() == plaintext.size() &&
                          Crypto::constantTimeEqual(verification.data(),
                                                    plaintext.data(),
                                                    plaintext.size());
    secureClear(verification);
    if (!verified) LittleFS.remove(path.c_str());
    return verified;
}

bool SecureStorage::unsealFromPath(const std::string& path,
                                   RecordType expectedType,
                                   uint32_t expectedId,
                                   std::vector<uint8_t>& plaintext,
                                   const uint8_t key[Crypto::KEY_SIZE]) {
    secureClear(plaintext);
    File file = LittleFS.open(path.c_str(), FILE_READ);
    if (!file || file.isDirectory() || file.size() < HEADER_SIZE ||
        file.size() > HEADER_SIZE + limits::RECORD_PLAINTEXT) {
        if (file) file.close();
        return false;
    }
    std::array<uint8_t, HEADER_SIZE> header{};
    if (file.read(header.data(), header.size()) != header.size()) {
        file.close();
        return false;
    }
    const uint16_t length = getU16(header.data() + 10);
    if (header[0] != 'V' || header[1] != 'K' || header[2] != 'R' ||
        header[3] != '1' || header[4] != FILE_SCHEMA ||
        header[5] != static_cast<uint8_t>(expectedType) ||
        getU32(header.data() + 6) != expectedId || length == 0 ||
        file.size() != HEADER_SIZE + length) {
        file.close();
        return false;
    }
    std::vector<uint8_t> ciphertext(length);
    if (file.read(ciphertext.data(), ciphertext.size()) != ciphertext.size()) {
        file.close();
        secureClear(ciphertext);
        return false;
    }
    file.close();
    plaintext.resize(length);
    const bool result = Crypto::aes256GcmDecrypt(
        key, header.data() + 12, header.data(), AAD_SIZE, ciphertext.data(),
        ciphertext.size(), header.data() + AAD_SIZE, plaintext.data());
    secureClear(ciphertext);
    if (!result) secureClear(plaintext);
    return result;
}

bool SecureStorage::atomicReplace(const std::string& temporary,
                                  const std::string& destination) {
    const std::string backup = destination + ".bak";
    LittleFS.remove(backup.c_str());
    const bool hadDestination = LittleFS.exists(destination.c_str());
    if (hadDestination &&
        !LittleFS.rename(destination.c_str(), backup.c_str())) {
        return false;
    }
    if (!LittleFS.rename(temporary.c_str(), destination.c_str())) {
        if (hadDestination) LittleFS.rename(backup.c_str(), destination.c_str());
        return false;
    }
    // Destination is already committed. A stale backup is harmless and is
    // removed by recoverTransactions() on the next boot.
    if (hadDestination) (void)LittleFS.remove(backup.c_str());
    return true;
}

bool SecureStorage::contains(RecordType type, uint32_t id) const {
    const auto& list = ids(type);
    return std::binary_search(list.begin(), list.end(), id);
}

std::vector<uint32_t>& SecureStorage::ids(RecordType type) {
    return type == RecordType::Credential ? credentialIds_ : totpIds_;
}

const std::vector<uint32_t>& SecureStorage::ids(RecordType type) const {
    return type == RecordType::Credential ? credentialIds_ : totpIds_;
}

const uint8_t* SecureStorage::keyFor(RecordType type) const {
    switch (type) {
        case RecordType::Credential: return credentialKey_.data();
        case RecordType::Totp: return totpKey_.data();
        case RecordType::Metadata: return metadataKey_.data();
    }
    return nullptr;
}

std::string SecureStorage::pathFor(RecordType type, uint32_t id) {
    char path[32]{};
    std::snprintf(path, sizeof(path), "/vault/%c_%08lX.vkr",
                  type == RecordType::Credential ? 'c' : 't',
                  static_cast<unsigned long>(id));
    return path;
}

bool SecureStorage::validType(RecordType type) {
    return type == RecordType::Credential || type == RecordType::Totp;
}

}  // namespace vaultkey
