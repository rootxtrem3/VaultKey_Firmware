#pragma once

#include <Arduino.h>

#include "core/HardwareConfig.h"

namespace vaultkey {

enum class LEDPattern { Startup, Normal, Unlock, AuthFailure, Warning, Error, Wipe };

// GPIO1 drives D1 through the on-board 1 kOhm current-limiting resistor.
// update() is non-blocking and is called from the main application loop.
class LED {
  public:
    bool begin() {
        if (!hardware::HAS_CONTROLLABLE_LED) return false;
        pinMode(hardware::PIN_STATUS_LED, OUTPUT);
        digitalWrite(hardware::PIN_STATUS_LED, LOW);
        available_ = true;
        set(LEDPattern::Startup);
        return true;
    }

    bool available() const { return available_; }

    void set(LEDPattern pattern) {
        pattern_ = pattern;
        patternStarted_ = millis();
        write(false);
    }

    void update() {
        if (!available_) return;
        const uint32_t elapsed = millis() - patternStarted_;
        bool on = false;
        switch (pattern_) {
            case LEDPattern::Startup:
                on = elapsed % 1600U < 90U;
                break;
            case LEDPattern::Normal:
                break;
            case LEDPattern::Unlock:
                on = true;
                break;
            case LEDPattern::AuthFailure: {
                const uint32_t phase = elapsed % 1400U;
                on = phase < 110U || (phase >= 230U && phase < 340U) ||
                     (phase >= 460U && phase < 570U);
                break;
            }
            case LEDPattern::Warning: {
                const uint32_t phase = elapsed % 1200U;
                on = phase < 120U || (phase >= 260U && phase < 380U);
                break;
            }
            case LEDPattern::Error:
                on = elapsed % 500U < 250U;
                break;
            case LEDPattern::Wipe:
                on = elapsed % 180U < 90U;
                break;
        }
        write(on);
    }

  private:
    void write(bool on) {
        if (available_) digitalWrite(hardware::PIN_STATUS_LED, on ? HIGH : LOW);
    }

    bool available_ = false;
    LEDPattern pattern_ = LEDPattern::Normal;
    uint32_t patternStarted_ = 0;
};

}  // namespace vaultkey
