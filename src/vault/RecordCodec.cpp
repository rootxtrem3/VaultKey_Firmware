#include "vault/RecordCodec.h"

#include <algorithm>
#include <cstddef>

#include "core/HardwareConfig.h"

namespace vaultkey {
namespace {

void putU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8U));
    out.push_back(static_cast<uint8_t>(value));
}

void putU32(std::vector<uint8_t>& out, uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

void putU64(std::vector<uint8_t>& out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

bool putString(std::vector<uint8_t>& out, const std::string& value,
               std::size_t limit) {
    if (value.size() > limit || value.size() > 0xFFFFU) {
        return false;
    }
    putU16(out, static_cast<uint16_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
    return true;
}

class Reader {
  public:
    explicit Reader(const std::vector<uint8_t>& input) : input_(input) {}

    bool u8(uint8_t& value) {
        if (remaining() < 1) return false;
        value = input_[position_++];
        return true;
    }

    bool u16(uint16_t& value) {
        if (remaining() < 2) return false;
        value = static_cast<uint16_t>(input_[position_]) << 8U |
                input_[position_ + 1];
        position_ += 2;
        return true;
    }

    bool u32(uint32_t& value) {
        if (remaining() < 4) return false;
        value = 0;
        for (int i = 0; i < 4; ++i) {
            value = (value << 8U) | input_[position_++];
        }
        return true;
    }

    bool u64(uint64_t& value) {
        if (remaining() < 8) return false;
        value = 0;
        for (int i = 0; i < 8; ++i) {
            value = (value << 8U) | input_[position_++];
        }
        return true;
    }

    bool string(std::string& value, std::size_t limit) {
        uint16_t length = 0;
        if (!u16(length) || length > limit || remaining() < length) {
            return false;
        }
        value.assign(reinterpret_cast<const char*>(input_.data() + position_),
                     length);
        position_ += length;
        return true;
    }

    bool bytes(std::vector<uint8_t>& value, std::size_t limit) {
        uint8_t length = 0;
        if (!u8(length) || length > limit || remaining() < length) {
            return false;
        }
        value.assign(input_.begin() + static_cast<std::ptrdiff_t>(position_),
                     input_.begin() +
                         static_cast<std::ptrdiff_t>(position_ + length));
        position_ += length;
        return true;
    }

    bool finished() const { return position_ == input_.size(); }

  private:
    std::size_t remaining() const { return input_.size() - position_; }
    const std::vector<uint8_t>& input_;
    std::size_t position_ = 0;
};

bool printableOrUtf8(const std::string& value) {
    return std::none_of(value.begin(), value.end(), [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return byte == 0 || byte < 0x09 || (byte > 0x0D && byte < 0x20);
    });
}

}  // namespace

bool RecordCodec::validate(const Credential& record) {
    return record.id != 0 && !record.service.empty() &&
           record.service.size() <= limits::SERVICE &&
           record.username.size() <= limits::USERNAME &&
           !record.password.empty() && record.password.size() <= limits::PASSWORD &&
           record.url.size() <= limits::URL && record.notes.size() <= limits::NOTES &&
           printableOrUtf8(record.service) && printableOrUtf8(record.username) &&
           printableOrUtf8(record.password) && printableOrUtf8(record.url) &&
           printableOrUtf8(record.notes);
}

bool RecordCodec::validate(const TotpEntry& record) {
    const bool algorithm = record.algorithm == HashAlgorithm::Sha1 ||
                           record.algorithm == HashAlgorithm::Sha256 ||
                           record.algorithm == HashAlgorithm::Sha512;
    return record.id != 0 && !record.issuer.empty() &&
           record.issuer.size() <= limits::ISSUER &&
           record.account.size() <= limits::ACCOUNT && !record.secret.empty() &&
           record.secret.size() <= limits::TOTP_SECRET && algorithm &&
           (record.digits == 6 || record.digits == 8) && record.period >= 15 &&
           record.period <= 300 && printableOrUtf8(record.issuer) &&
           printableOrUtf8(record.account);
}

bool RecordCodec::encode(const Credential& record,
                         std::vector<uint8_t>& output) {
    output.clear();
    if (!validate(record)) return false;
    output.reserve(32 + record.service.size() + record.username.size() +
                   record.password.size() + record.url.size() + record.notes.size());
    output.push_back(VERSION);
    output.push_back(static_cast<uint8_t>(RecordType::Credential));
    putU32(output, record.id);
    putU64(output, record.createdAt);
    return putString(output, record.service, limits::SERVICE) &&
           putString(output, record.username, limits::USERNAME) &&
           putString(output, record.password, limits::PASSWORD) &&
           putString(output, record.url, limits::URL) &&
           putString(output, record.notes, limits::NOTES) &&
           output.size() <= limits::RECORD_PLAINTEXT;
}

bool RecordCodec::decode(const std::vector<uint8_t>& input, Credential& record) {
    record.clearSensitive();
    record.service.clear();
    Reader reader(input);
    uint8_t version = 0;
    uint8_t type = 0;
    if (!reader.u8(version) || version != VERSION || !reader.u8(type) ||
        type != static_cast<uint8_t>(RecordType::Credential) ||
        !reader.u32(record.id) || !reader.u64(record.createdAt) ||
        !reader.string(record.service, limits::SERVICE) ||
        !reader.string(record.username, limits::USERNAME) ||
        !reader.string(record.password, limits::PASSWORD) ||
        !reader.string(record.url, limits::URL) ||
        !reader.string(record.notes, limits::NOTES) || !reader.finished() ||
        !validate(record)) {
        record.clearSensitive();
        record.service.clear();
        record.id = 0;
        return false;
    }
    return true;
}

bool RecordCodec::encode(const TotpEntry& record,
                         std::vector<uint8_t>& output) {
    output.clear();
    if (!validate(record)) return false;
    output.reserve(32 + record.issuer.size() + record.account.size() +
                   record.secret.size());
    output.push_back(VERSION);
    output.push_back(static_cast<uint8_t>(RecordType::Totp));
    putU32(output, record.id);
    putU64(output, record.createdAt);
    if (!putString(output, record.issuer, limits::ISSUER) ||
        !putString(output, record.account, limits::ACCOUNT)) {
        return false;
    }
    output.push_back(static_cast<uint8_t>(record.secret.size()));
    output.insert(output.end(), record.secret.begin(), record.secret.end());
    output.push_back(static_cast<uint8_t>(record.algorithm));
    output.push_back(record.digits);
    putU16(output, record.period);
    return output.size() <= limits::RECORD_PLAINTEXT;
}

bool RecordCodec::decode(const std::vector<uint8_t>& input, TotpEntry& record) {
    record.clearSensitive();
    record.issuer.clear();
    record.account.clear();
    Reader reader(input);
    uint8_t version = 0;
    uint8_t type = 0;
    uint8_t algorithm = 0;
    if (!reader.u8(version) || version != VERSION || !reader.u8(type) ||
        type != static_cast<uint8_t>(RecordType::Totp) ||
        !reader.u32(record.id) || !reader.u64(record.createdAt) ||
        !reader.string(record.issuer, limits::ISSUER) ||
        !reader.string(record.account, limits::ACCOUNT) ||
        !reader.bytes(record.secret, limits::TOTP_SECRET) ||
        !reader.u8(algorithm) || !reader.u8(record.digits) ||
        !reader.u16(record.period) || !reader.finished()) {
        record.clearSensitive();
        record.id = 0;
        return false;
    }
    record.algorithm = static_cast<HashAlgorithm>(algorithm);
    if (!validate(record)) {
        record.clearSensitive();
        record.issuer.clear();
        record.account.clear();
        record.id = 0;
        return false;
    }
    return true;
}

}  // namespace vaultkey
