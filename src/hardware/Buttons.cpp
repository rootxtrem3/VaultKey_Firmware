#include "hardware/Buttons.h"

#include <Arduino.h>

#include "core/HardwareConfig.h"

namespace vaultkey {

void Buttons::begin() {
    states_[index(ButtonId::Up)].pin = hardware::PIN_BUTTON_UP;
    states_[index(ButtonId::Down)].pin = hardware::PIN_BUTTON_DOWN;
    states_[index(ButtonId::Select)].pin = hardware::PIN_BUTTON_SELECT;
    states_[index(ButtonId::Back)].pin = hardware::PIN_BUTTON_BACK;
    const uint32_t now = millis();
    for (State& state : states_) {
        pinMode(state.pin, INPUT_PULLUP);
        state.raw = digitalRead(state.pin) == LOW;
        state.stable = state.raw;
        state.rawChangedAt = now;
        state.pressedAt = state.stable ? now : 0;
        state.nextRepeatAt = now + REPEAT_DELAY_MS;
    }
}

void Buttons::update(uint32_t nowMs) {
    for (std::size_t current = 0; current < states_.size(); ++current) {
        State& state = states_[current];
        const ButtonId button = static_cast<ButtonId>(current);
        const bool raw = digitalRead(state.pin) == LOW;
        if (raw != state.raw) {
            state.raw = raw;
            state.rawChangedAt = nowMs;
        }

        if (raw != state.stable && nowMs - state.rawChangedAt >= DEBOUNCE_MS) {
            state.stable = raw;
            if (state.stable) {
                state.pressedAt = nowMs;
                state.nextRepeatAt = nowMs + REPEAT_DELAY_MS;
                state.longSent = false;
                state.repeated = false;
                push(button, ButtonEventType::Pressed, nowMs, 0);
            } else {
                const uint32_t held = nowMs - state.pressedAt;
                push(button, ButtonEventType::Released, nowMs, held);
                if (!state.longSent && !state.repeated) {
                    push(button, ButtonEventType::ShortPress, nowMs, held);
                }
            }
        }

        if (!state.stable) continue;
        const uint32_t held = nowMs - state.pressedAt;
        const uint32_t longThreshold =
            button == ButtonId::Back ? BACK_LOCK_MS : LONG_PRESS_MS;
        if (!state.longSent && held >= longThreshold) {
            state.longSent = true;
            push(button, ButtonEventType::LongPress, nowMs, held);
        }
        if ((button == ButtonId::Up || button == ButtonId::Down) &&
            static_cast<int32_t>(nowMs - state.nextRepeatAt) >= 0) {
            state.repeated = true;
            push(button, ButtonEventType::Repeat, nowMs, held);
            state.nextRepeatAt = nowMs + REPEAT_INTERVAL_MS;
        }
    }
}

void Buttons::push(ButtonId button, ButtonEventType type, uint32_t nowMs,
                   uint32_t heldMs) {
    if (queueCount_ == QUEUE_SIZE) {
        ++droppedEvents_;
        return;
    }
    queue_[queueTail_] = {button, type, nowMs, heldMs};
    queueTail_ = (queueTail_ + 1) % QUEUE_SIZE;
    ++queueCount_;
}

bool Buttons::pop(ButtonEvent& event) {
    if (queueCount_ == 0) return false;
    event = queue_[queueHead_];
    queueHead_ = (queueHead_ + 1) % QUEUE_SIZE;
    --queueCount_;
    return true;
}

bool Buttons::isDown(ButtonId button) const {
    return states_[index(button)].stable;
}

uint32_t Buttons::heldFor(ButtonId button, uint32_t nowMs) const {
    const State& state = states_[index(button)];
    return state.stable ? nowMs - state.pressedAt : 0;
}

}  // namespace vaultkey
