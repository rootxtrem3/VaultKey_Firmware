#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "security/Crypto.h"
#include "security/SecureZero.h"
#include "vault/Models.h"

namespace vaultkey {

enum class StorageStatus : uint8_t {
    NotInitialized,
    Ready,
    MountFailed,
    FormatFailed,
    ManifestCorrupt,
    RecordCorrupt,
    IoError,
    Locked
};

class SecureStorage {
  public:
    bool begin(bool allowFormat);
    bool unlock(const uint8_t masterKey[Crypto::KEY_SIZE]);
    void lock();
    bool unlocked() const { return unlocked_; }
    bool healthy() const { return status_ == StorageStatus::Ready; }
    StorageStatus status() const { return status_; }
    const char* statusText() const;

    bool writeRecord(RecordType type, uint32_t id,
                     const std::vector<uint8_t>& plaintext);
    bool readRecord(RecordType type, uint32_t id,
                    std::vector<uint8_t>& plaintext);
    bool deleteRecord(RecordType type, uint32_t id);
    std::vector<uint32_t> listIds(RecordType type) const;
    bool wipe();

  private:
    static constexpr uint8_t FILE_SCHEMA = 1;
    static constexpr std::size_t AAD_SIZE = 24;
    static constexpr std::size_t HEADER_SIZE = 40;
    static constexpr uint32_t MANIFEST_MAGIC = 0x564D4631U;  // VMF1

    bool recoverTransactions();
    bool initializeManifest();
    bool loadManifest();
    bool saveManifest();
    bool verifyManifestRecords();
    bool sealToPath(const std::string& path, RecordType type, uint32_t id,
                    const std::vector<uint8_t>& plaintext,
                    const uint8_t key[Crypto::KEY_SIZE]);
    bool unsealFromPath(const std::string& path, RecordType expectedType,
                        uint32_t expectedId, std::vector<uint8_t>& plaintext,
                        const uint8_t key[Crypto::KEY_SIZE]);
    bool atomicReplace(const std::string& temporary,
                       const std::string& destination);
    bool contains(RecordType type, uint32_t id) const;
    std::vector<uint32_t>& ids(RecordType type);
    const std::vector<uint32_t>& ids(RecordType type) const;
    const uint8_t* keyFor(RecordType type) const;
    static std::string pathFor(RecordType type, uint32_t id);
    static bool validType(RecordType type);

    SecureBytes<Crypto::KEY_SIZE> credentialKey_;
    SecureBytes<Crypto::KEY_SIZE> totpKey_;
    SecureBytes<Crypto::KEY_SIZE> metadataKey_;
    std::vector<uint32_t> credentialIds_;
    std::vector<uint32_t> totpIds_;
    uint32_t manifestGeneration_ = 0;
    StorageStatus status_ = StorageStatus::NotInitialized;
    bool mounted_ = false;
    bool unlocked_ = false;
};

}  // namespace vaultkey
