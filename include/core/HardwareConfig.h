#pragma once

#include <cstddef>
#include <cstdint>

#ifndef VAULTKEY_FIRMWARE_VERSION
#define VAULTKEY_FIRMWARE_VERSION "development"
#endif

#ifndef VAULTKEY_HARDWARE_VERSION
#define VAULTKEY_HARDWARE_VERSION "rev-D"
#endif

namespace vaultkey::hardware {

// Schematic-derived ESP32-S3-WROOM-1U assignments. Do not change these
// without changing and re-verifying the rev-D schematic and PCB.
inline constexpr int PIN_BUTTON_SELECT = 4;  // U1.4, SW_SELECT
inline constexpr int PIN_BUTTON_DOWN = 5;    // U1.5, SW_DOWN
inline constexpr int PIN_BUTTON_BACK = 6;    // U1.6, SW_BACK
inline constexpr int PIN_BUTTON_UP = 7;      // U1.7, SW_UP
inline constexpr int PIN_I2C_SDA = 8;        // U1.12, OLED_SDA
inline constexpr int PIN_I2C_SCL = 9;        // U1.17, OLED_SCL
inline constexpr int PIN_OLED_RESET = 13;    // U1.21, OLED_RST
inline constexpr int PIN_USB_DM = 19;         // U1.13, USB_D-/GPIO19
inline constexpr int PIN_USB_DP = 20;         // U1.14, USB_D+/GPIO20
inline constexpr int PIN_BOOT = 0;            // U1.27, pulled high by R7

inline constexpr uint8_t OLED_ADDRESS = 0x3C;
inline constexpr uint8_t RTC_ADDRESS = 0x68;
inline constexpr int OLED_WIDTH = 128;
inline constexpr int OLED_HEIGHT = 64;
inline constexpr uint32_t I2C_FREQUENCY_HZ = 100000;

// D1 is wired from 3.3 V through R5 to ground. It is a power indicator and
// has no MCU GPIO, so firmware status patterns are unavailable on rev-D.
inline constexpr bool HAS_CONTROLLABLE_LED = false;
inline constexpr bool HAS_BOOT_CONTROL = false;
inline constexpr bool HAS_RTC_INTERRUPT = false;
inline constexpr bool HAS_BUZZER = false;

inline constexpr const char* FIRMWARE_VERSION = VAULTKEY_FIRMWARE_VERSION;
inline constexpr const char* HARDWARE_VERSION = VAULTKEY_HARDWARE_VERSION;

}  // namespace vaultkey::hardware

namespace vaultkey::limits {
inline constexpr std::size_t PIN_DIGITS = 6;
inline constexpr std::size_t SERVICE = 64;
inline constexpr std::size_t USERNAME = 128;
inline constexpr std::size_t PASSWORD = 256;
inline constexpr std::size_t URL = 192;
inline constexpr std::size_t NOTES = 512;
inline constexpr std::size_t ISSUER = 64;
inline constexpr std::size_t ACCOUNT = 96;
inline constexpr std::size_t TOTP_SECRET = 64;
inline constexpr std::size_t USB_LINE = 2048;
inline constexpr std::size_t RECORD_PLAINTEXT = 2048;
inline constexpr std::size_t MAX_CREDENTIALS = 128;
inline constexpr std::size_t MAX_TOTP_ENTRIES = 128;
}  // namespace vaultkey::limits
