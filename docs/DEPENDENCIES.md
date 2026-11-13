# Pinned build dependencies

| Component | Version | Source/purpose |
|---|---:|---|
| PlatformIO Core | 6.2.0 used for release | Build/test runner |
| PlatformIO `espressif32` | 8.0.0 | ESP32 platform |
| Arduino-ESP32 | 3.3.12 (`4.30312.261024`) | Arduino framework, TinyUSB, LittleFS, Preferences |
| ESP32-S3 prebuilt libraries | 3.3.12 | ESP-IDF/mbedTLS target libraries |
| ESP-IDF embedded in release | 5.5.5 | Reported by `esptool image-info` |
| Adafruit SSD1306 | 2.5.17 | SSD1306 display driver |
| Adafruit GFX | 1.13.0 | Display graphics/text |
| Adafruit BusIO | 1.17.4 (transitive) | Adafruit I²C abstraction |
| ArduinoJson | 7.4.3 | Bounded JSON Lines protocol parsing |
| Unity | 2.6.1 | Native unit-test framework |
| OpenSSL | 4.1.0 used for release tests | Independent native crypto test backend |

Production firmware cryptography uses ESP32-S3 mbedTLS and the ESP hardware
random generator. OpenSSL is used only by the host-native known-answer tests.

`FS`, `LittleFS`, `Preferences`, `Wire`, and `USB` are framework libraries from
the pinned Arduino-ESP32 package. `scripts/framework_paths.py` works around a
PlatformIO 8.0.0 transitive include-path issue between Arduino's USB and FS
libraries; it resolves the package directory dynamically.
