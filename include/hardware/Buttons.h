#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace vaultkey {

enum class ButtonId : uint8_t { Up = 0, Down = 1, Select = 2, Back = 3 };
enum class ButtonEventType : uint8_t {
    Pressed,
    Released,
    ShortPress,
    LongPress,
    Repeat
};

struct ButtonEvent {
    ButtonId button = ButtonId::Up;
    ButtonEventType type = ButtonEventType::Pressed;
    uint32_t timestampMs = 0;
    uint32_t heldMs = 0;
};

class Buttons {
  public:
    static constexpr uint32_t DEBOUNCE_MS = 30;
    static constexpr uint32_t LONG_PRESS_MS = 700;
    static constexpr uint32_t BACK_LOCK_MS = 2000;
    static constexpr uint32_t REPEAT_DELAY_MS = 350;
    static constexpr uint32_t REPEAT_INTERVAL_MS = 150;

    void begin();
    void update(uint32_t nowMs);
    bool pop(ButtonEvent& event);
    bool isDown(ButtonId button) const;
    uint32_t heldFor(ButtonId button, uint32_t nowMs) const;
    uint32_t droppedEvents() const { return droppedEvents_; }

  private:
    struct State {
        int pin = -1;
        bool raw = false;
        bool stable = false;
        bool longSent = false;
        bool repeated = false;
        uint32_t rawChangedAt = 0;
        uint32_t pressedAt = 0;
        uint32_t nextRepeatAt = 0;
    };

    static constexpr std::size_t QUEUE_SIZE = 32;
    void push(ButtonId button, ButtonEventType type, uint32_t nowMs,
              uint32_t heldMs);
    static std::size_t index(ButtonId button) {
        return static_cast<std::size_t>(button);
    }

    std::array<State, 4> states_{};
    std::array<ButtonEvent, QUEUE_SIZE> queue_{};
    std::size_t queueHead_ = 0;
    std::size_t queueTail_ = 0;
    std::size_t queueCount_ = 0;
    uint32_t droppedEvents_ = 0;
};

}  // namespace vaultkey
