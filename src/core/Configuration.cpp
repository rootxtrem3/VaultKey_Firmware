#include "core/Configuration.h"

namespace vaultkey {

bool Configuration::begin() {
    open_ = preferences_.begin("vkcfg", false);
    if (!open_) return false;
    const uint16_t schema = preferences_.getUShort("schema", 0);
    if (schema > SCHEMA_VERSION) return false;
    if (schema == 0) {
        settings_ = DeviceSettings{};
        return save();
    }
    settings_.idleTimeoutSeconds = preferences_.getUShort("idle", 300);
    settings_.timezoneMinutes = preferences_.getShort("tz", 0);
    settings_.displayContrast = preferences_.getUChar("contrast", 0xCF);
    settings_.keyboardLayout = static_cast<KeyboardLayout>(
        preferences_.getUChar("layout", 0));
    settings_.hidKeystrokeDelayMs = preferences_.getUShort("hid_delay", 20);
    if (!valid(settings_)) {
        settings_ = DeviceSettings{};
        return save();
    }
    return true;
}

bool Configuration::save() {
    if (!open_ || !valid(settings_)) return false;
    return preferences_.putUShort("idle", settings_.idleTimeoutSeconds) ==
               sizeof(uint16_t) &&
           preferences_.putShort("tz", settings_.timezoneMinutes) ==
               sizeof(int16_t) &&
           preferences_.putUChar("contrast", settings_.displayContrast) ==
               sizeof(uint8_t) &&
           preferences_.putUChar(
               "layout", static_cast<uint8_t>(settings_.keyboardLayout)) ==
               sizeof(uint8_t) &&
           preferences_.putUShort("hid_delay",
                                  settings_.hidKeystrokeDelayMs) ==
               sizeof(uint16_t) &&
           preferences_.putUShort("schema", SCHEMA_VERSION) ==
               sizeof(uint16_t);
}

bool Configuration::reset() {
    if (!open_ || !preferences_.clear()) return false;
    settings_ = DeviceSettings{};
    return save();
}

bool Configuration::valid(const DeviceSettings& settings) {
    return settings.idleTimeoutSeconds >= 30 &&
           settings.idleTimeoutSeconds <= 3600 &&
           settings.timezoneMinutes >= -12 * 60 &&
           settings.timezoneMinutes <= 14 * 60 &&
           static_cast<uint8_t>(settings.keyboardLayout) <=
               static_cast<uint8_t>(KeyboardLayout::PtBR) &&
           settings.hidKeystrokeDelayMs >= 5 &&
           settings.hidKeystrokeDelayMs <= 250;
}

const char* Configuration::keyboardLayoutName(KeyboardLayout layout) {
    switch (layout) {
        case KeyboardLayout::EnUS: return "en-US";
        case KeyboardLayout::DeDE: return "de-DE";
        case KeyboardLayout::EsES: return "es-ES";
        case KeyboardLayout::FrFR: return "fr-FR";
        case KeyboardLayout::ItIT: return "it-IT";
        case KeyboardLayout::PtPT: return "pt-PT";
        case KeyboardLayout::SvSE: return "sv-SE";
        case KeyboardLayout::DaDK: return "da-DK";
        case KeyboardLayout::HuHU: return "hu-HU";
        case KeyboardLayout::JaJP: return "ja-JP";
        case KeyboardLayout::PtBR: return "pt-BR";
    }
    return "unknown";
}

}  // namespace vaultkey
