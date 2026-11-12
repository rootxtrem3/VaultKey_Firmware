#pragma once

#include <USB.h>
#include <USBCDC.h>
#include <USBHID.h>
#include <USBHIDKeyboard.h>

#include <cstdint>
#include <string>

#include "core/Configuration.h"

#if !defined(ARDUINO_USB_MODE) || ARDUINO_USB_MODE != 0
#error "VaultKey CDC+HID requires ESP32-S3 USB-OTG/TinyUSB mode"
#endif

namespace vaultkey {

class USBComposite {
  public:
    USBComposite();
    bool begin(KeyboardLayout layout);
    void update(uint32_t nowMs);
    void setKeyboardLayout(KeyboardLayout layout);

    bool driverStarted() const { return driverStarted_; }
    bool mounted() const { return mounted_; }
    bool suspended() const { return suspended_; }
    bool cdcConnected() const;
    bool hidReady();
    Stream& cdc() { return cdc_; }

    bool typeAuthorized(const std::string& text, uint16_t delayMs);
    void cancelTyping();
    bool typing() const { return typing_; }

  private:
    static USBComposite* active_;
    static const uint8_t* layoutTable(KeyboardLayout layout);
    static void usbEvent(void* argument, esp_event_base_t base, int32_t eventId,
                         void* eventData);
    static void cdcEvent(void* argument, esp_event_base_t base, int32_t eventId,
                         void* eventData);

    USBCDC cdc_;
    // Keep keyboard before statusHid_: the first USBHID constructor chooses
    // the interface protocol and must select keyboard boot protocol.
    USBHIDKeyboard keyboard_;
    USBHID statusHid_;
    std::string pendingText_;
    std::size_t pendingOffset_ = 0;
    uint32_t nextKeystrokeAt_ = 0;
    uint16_t keystrokeDelayMs_ = 20;
    volatile bool mounted_ = false;
    volatile bool suspended_ = false;
    bool driverStarted_ = false;
    bool typing_ = false;
};

}  // namespace vaultkey
