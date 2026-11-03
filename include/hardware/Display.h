#pragma once

#include <Adafruit_SSD1306.h>
#include <Wire.h>

#include <cstdint>
#include <string>

namespace vaultkey {

class Display {
  public:
    Display();
    bool begin(TwoWire& wire);
    bool ready() const { return ready_; }
    void setContrast(uint8_t contrast);

    void showBoot(const char* phase = "Initializing...");
    void showError(const char* title, const char* message);
    void beginFrame(const char* title, const char* status = nullptr);
    void text(int16_t x, int16_t y, const std::string& value,
              bool inverted = false);
    void centered(int16_t y, const std::string& value, uint8_t size = 1);
    void progress(int16_t x, int16_t y, int16_t width, int16_t height,
                  uint16_t value, uint16_t maximum);
    void separator(int16_t y);
    void commit();

  private:
    static std::string clipped(const std::string& value, std::size_t columns);
    Adafruit_SSD1306 oled_;
    bool ready_ = false;
};

}  // namespace vaultkey
