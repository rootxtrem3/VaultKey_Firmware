#pragma once

#include <Wire.h>

#include <cstdint>

#include "core/TimeUtils.h"

namespace vaultkey {

enum class RTCStatus : uint8_t {
    NotInitialized,
    Ready,
    NotFound,
    OscillatorStopped,
    InvalidBcd,
    InvalidCalendar,
    IoError
};

class RTC {
  public:
    bool begin(TwoWire& wire);
    void update(uint32_t nowMs);
    bool read();
    bool now(uint64_t& unixTime) const;
    bool setUnix(uint64_t unixTime);
    bool valid() const { return status_ == RTCStatus::Ready; }
    bool present() const { return present_; }
    RTCStatus status() const { return status_; }
    const char* statusText() const;

  private:
    static bool validBcd(uint8_t value);
    static uint8_t fromBcd(uint8_t value);
    static uint8_t toBcd(uint8_t value);
    TwoWire* wire_ = nullptr;
    RTCStatus status_ = RTCStatus::NotInitialized;
    bool present_ = false;
    uint64_t baseUnix_ = 0;
    uint32_t baseMillis_ = 0;
    uint32_t lastReadAttempt_ = 0;
};

}  // namespace vaultkey
