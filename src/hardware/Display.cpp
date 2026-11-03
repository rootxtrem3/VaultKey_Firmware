#include "hardware/Display.h"

#include <algorithm>

#include "core/HardwareConfig.h"

namespace vaultkey {

Display::Display()
    : oled_(hardware::OLED_WIDTH, hardware::OLED_HEIGHT, &Wire,
            hardware::PIN_OLED_RESET) {}

bool Display::begin(TwoWire& wire) {
    (void)wire;
    ready_ = oled_.begin(SSD1306_SWITCHCAPVCC, hardware::OLED_ADDRESS, true,
                         false);
    if (!ready_) return false;
    oled_.setTextColor(SSD1306_WHITE);
    oled_.setTextWrap(false);
    oled_.clearDisplay();
    oled_.display();
    return true;
}

void Display::setContrast(uint8_t contrast) {
    if (!ready_) return;
    oled_.ssd1306_command(SSD1306_SETCONTRAST);
    oled_.ssd1306_command(contrast);
}

void Display::showBoot(const char* phase) {
    if (!ready_) return;
    oled_.clearDisplay();
    centered(13, "VAULTKEY", 2);
    centered(36, "Secure Vault");
    centered(51, phase == nullptr ? "Initializing..." : phase);
    commit();
}

void Display::showError(const char* title, const char* message) {
    if (!ready_) return;
    beginFrame(title == nullptr ? "ERROR" : title, "!");
    text(0, 18, clipped(message == nullptr ? "Unknown failure" : message, 21));
    commit();
}

void Display::beginFrame(const char* title, const char* status) {
    if (!ready_) return;
    oled_.clearDisplay();
    oled_.setTextSize(1);
    oled_.setTextColor(SSD1306_WHITE);
    oled_.setCursor(0, 0);
    oled_.print(clipped(title == nullptr ? "VAULTKEY" : title, 17).c_str());
    if (status != nullptr) {
        const std::string clippedStatus = clipped(status, 4);
        const int16_t x = hardware::OLED_WIDTH -
                          static_cast<int16_t>(clippedStatus.size() * 6U);
        oled_.setCursor(std::max<int16_t>(0, x), 0);
        oled_.print(clippedStatus.c_str());
    }
    separator(9);
}

void Display::text(int16_t x, int16_t y, const std::string& value,
                   bool inverted) {
    if (!ready_ || y < 0 || y >= hardware::OLED_HEIGHT) return;
    oled_.setTextSize(1);
    if (inverted) {
        oled_.fillRect(x, y - 1, hardware::OLED_WIDTH - x, 9, SSD1306_WHITE);
        oled_.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
    } else {
        oled_.setTextColor(SSD1306_WHITE, SSD1306_BLACK);
    }
    oled_.setCursor(x, y);
    const std::size_t columns =
        x >= hardware::OLED_WIDTH
            ? 0
            : static_cast<std::size_t>((hardware::OLED_WIDTH - x) / 6);
    oled_.print(clipped(value, columns).c_str());
    oled_.setTextColor(SSD1306_WHITE, SSD1306_BLACK);
}

void Display::centered(int16_t y, const std::string& value, uint8_t size) {
    if (!ready_) return;
    oled_.setTextSize(size);
    const int16_t width = static_cast<int16_t>(value.size() * 6U * size);
    oled_.setCursor(std::max<int16_t>(0, (hardware::OLED_WIDTH - width) / 2), y);
    oled_.setTextColor(SSD1306_WHITE);
    oled_.print(value.c_str());
    oled_.setTextSize(1);
}

void Display::progress(int16_t x, int16_t y, int16_t width, int16_t height,
                       uint16_t value, uint16_t maximum) {
    if (!ready_ || width < 3 || height < 3 || maximum == 0) return;
    value = std::min(value, maximum);
    oled_.drawRect(x, y, width, height, SSD1306_WHITE);
    const int16_t interior = width - 2;
    const int16_t fill = static_cast<int16_t>(
        (static_cast<uint32_t>(interior) * value) / maximum);
    if (fill > 0) oled_.fillRect(x + 1, y + 1, fill, height - 2, SSD1306_WHITE);
}

void Display::separator(int16_t y) {
    if (ready_) oled_.drawFastHLine(0, y, hardware::OLED_WIDTH, SSD1306_WHITE);
}

void Display::commit() {
    if (ready_) oled_.display();
}

std::string Display::clipped(const std::string& value, std::size_t columns) {
    if (value.size() <= columns) return value;
    if (columns <= 3) return value.substr(0, columns);
    return value.substr(0, columns - 3) + "...";
}

}  // namespace vaultkey
