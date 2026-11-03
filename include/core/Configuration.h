#pragma once

#include <Preferences.h>

#include <cstdint>

namespace vaultkey {

enum class KeyboardLayout : uint8_t {
    EnUS = 0,
    DeDE,
    EsES,
    FrFR,
    ItIT,
    PtPT,
    SvSE,
    DaDK,
    HuHU,
    JaJP,
    PtBR
};

struct DeviceSettings {
    uint16_t idleTimeoutSeconds = 300;
    int16_t timezoneMinutes = 0;
    uint8_t displayContrast = 0xCF;
    KeyboardLayout keyboardLayout = KeyboardLayout::EnUS;
    uint16_t hidKeystrokeDelayMs = 20;
};

class Configuration {
  public:
    static constexpr uint16_t SCHEMA_VERSION = 1;
    bool begin();
    bool save();
    bool reset();
    const DeviceSettings& settings() const { return settings_; }
    DeviceSettings& settings() { return settings_; }
    static const char* keyboardLayoutName(KeyboardLayout layout);

  private:
    static bool valid(const DeviceSettings& settings);
    Preferences preferences_;
    DeviceSettings settings_{};
    bool open_ = false;
};

}  // namespace vaultkey
