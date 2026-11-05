#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vaultkey {

inline void secureZero(void* pointer, std::size_t length) {
    volatile uint8_t* bytes = static_cast<volatile uint8_t*>(pointer);
    while (length-- > 0) {
        *bytes++ = 0;
    }
}

inline void secureClear(std::string& value) {
    if (!value.empty()) {
        secureZero(value.data(), value.size());
    }
    value.clear();
    value.shrink_to_fit();
}

inline void secureClear(std::vector<uint8_t>& value) {
    if (!value.empty()) {
        secureZero(value.data(), value.size());
    }
    value.clear();
    value.shrink_to_fit();
}

template <std::size_t N>
class SecureBytes {
  public:
    SecureBytes() = default;
    ~SecureBytes() { clear(); }
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    uint8_t* data() { return bytes_; }
    const uint8_t* data() const { return bytes_; }
    constexpr std::size_t size() const { return N; }
    bool valid() const { return valid_; }
    void markValid() { valid_ = true; }
    void clear() {
        secureZero(bytes_, N);
        valid_ = false;
    }

  private:
    uint8_t bytes_[N]{};
    bool valid_ = false;
};

}  // namespace vaultkey
