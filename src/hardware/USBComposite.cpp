#include "hardware/USBComposite.h"

#include <Arduino.h>

#include <algorithm>

#include "security/SecureZero.h"

namespace vaultkey {

USBComposite* USBComposite::active_ = nullptr;

USBComposite::USBComposite() : statusHid_(HID_ITF_PROTOCOL_KEYBOARD) {}

bool USBComposite::begin(KeyboardLayout layout) {
    if (active_ != nullptr && active_ != this) return false;
    active_ = this;
    USB.productName("VaultKey");
    USB.manufacturerName("VaultKey");
    USB.serialNumber("__MAC__");
    USB.usbPower(500);
    USB.usbAttributes(0);  // Bus-powered; bmAttributes bit 7 is added by USB.
    USB.onEvent(usbEvent);
    cdc_.onEvent(cdcEvent);
    cdc_.enableReboot(true);
    cdc_.begin(115200);
    keyboard_.begin(layoutTable(layout));
    driverStarted_ = USB.begin();
    return driverStarted_;
}

void USBComposite::update(uint32_t nowMs) {
    if (!typing_) return;
    if (!mounted_ || suspended_ || !hidReady()) {
        cancelTyping();
        return;
    }
    if (static_cast<int32_t>(nowMs - nextKeystrokeAt_) < 0) return;
    if (pendingOffset_ >= pendingText_.size()) {
        keyboard_.releaseAll();
        secureClear(pendingText_);
        pendingOffset_ = 0;
        typing_ = false;
        return;
    }
    const uint8_t character =
        static_cast<uint8_t>(pendingText_[pendingOffset_]);
    // Arduino's keyboard layout tables support printable ASCII, tab, newline,
    // and backspace. Provisioning may store UTF-8, but HID refuses unsupported
    // bytes instead of emitting an incorrect key sequence.
    const bool supported = (character >= 0x20U && character <= 0x7EU) ||
                           character == '\t' || character == '\n' ||
                           character == '\b';
    if (!supported || keyboard_.write(character) != 1) {
        cancelTyping();
        return;
    }
    ++pendingOffset_;
    nextKeystrokeAt_ = nowMs + keystrokeDelayMs_;
}

void USBComposite::setKeyboardLayout(KeyboardLayout layout) {
    keyboard_.begin(layoutTable(layout));
}

bool USBComposite::cdcConnected() const {
    return driverStarted_ && static_cast<bool>(cdc_);
}

bool USBComposite::hidReady() {
    return driverStarted_ && mounted_ && !suspended_ && statusHid_.ready();
}

bool USBComposite::typeAuthorized(const std::string& text, uint16_t delayMs) {
    if (typing_ || text.empty() || !hidReady()) return false;
    if (!std::all_of(text.begin(), text.end(), [](char value) {
            const uint8_t byte = static_cast<uint8_t>(value);
            return (byte >= 0x20U && byte <= 0x7EU) || byte == '\t' ||
                   byte == '\n' || byte == '\b';
        })) {
        return false;
    }
    pendingText_ = text;
    pendingOffset_ = 0;
    keystrokeDelayMs_ = std::clamp<uint16_t>(delayMs, 5, 250);
    nextKeystrokeAt_ = millis();
    typing_ = true;
    return true;
}

void USBComposite::cancelTyping() {
    keyboard_.releaseAll();
    secureClear(pendingText_);
    pendingOffset_ = 0;
    typing_ = false;
}

const uint8_t* USBComposite::layoutTable(KeyboardLayout layout) {
    switch (layout) {
        case KeyboardLayout::EnUS: return KeyboardLayout_en_US;
        case KeyboardLayout::DeDE: return KeyboardLayout_de_DE;
        case KeyboardLayout::EsES: return KeyboardLayout_es_ES;
        case KeyboardLayout::FrFR: return KeyboardLayout_fr_FR;
        case KeyboardLayout::ItIT: return KeyboardLayout_it_IT;
        case KeyboardLayout::PtPT: return KeyboardLayout_pt_PT;
        case KeyboardLayout::SvSE: return KeyboardLayout_sv_SE;
        case KeyboardLayout::DaDK: return KeyboardLayout_da_DK;
        case KeyboardLayout::HuHU: return KeyboardLayout_hu_HU;
        case KeyboardLayout::JaJP: return KeyboardLayout_ja_JP;
        case KeyboardLayout::PtBR: return KeyboardLayout_pt_BR;
    }
    return KeyboardLayout_en_US;
}

void USBComposite::usbEvent(void* argument, esp_event_base_t base,
                            int32_t eventId, void* eventData) {
    (void)argument;
    (void)eventData;
    if (base != ARDUINO_USB_EVENTS || active_ == nullptr) return;
    switch (eventId) {
        case ARDUINO_USB_STARTED_EVENT:
            active_->mounted_ = true;
            active_->suspended_ = false;
            break;
        case ARDUINO_USB_STOPPED_EVENT:
            active_->mounted_ = false;
            active_->suspended_ = false;
            break;
        case ARDUINO_USB_SUSPEND_EVENT:
            active_->suspended_ = true;
            break;
        case ARDUINO_USB_RESUME_EVENT:
            active_->suspended_ = false;
            break;
        default:
            break;
    }
}

void USBComposite::cdcEvent(void* argument, esp_event_base_t base,
                            int32_t eventId, void* eventData) {
    (void)argument;
    (void)base;
    (void)eventId;
    (void)eventData;
}

}  // namespace vaultkey
