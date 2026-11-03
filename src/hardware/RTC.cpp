#include "hardware/RTC.h"

#include <Arduino.h>

#include "core/HardwareConfig.h"

namespace vaultkey {

bool RTC::begin(TwoWire& wire) {
    wire_ = &wire;
    status_ = RTCStatus::NotInitialized;
    return read();
}

void RTC::update(uint32_t nowMs) {
    const uint32_t interval = valid() ? 10000U : 2000U;
    if (nowMs - lastReadAttempt_ >= interval) read();
}

bool RTC::read() {
    if (wire_ == nullptr) {
        status_ = RTCStatus::NotInitialized;
        return false;
    }
    lastReadAttempt_ = millis();
    wire_->beginTransmission(hardware::RTC_ADDRESS);
    wire_->write(static_cast<uint8_t>(0));
    if (wire_->endTransmission(false) != 0) {
        present_ = false;
        status_ = RTCStatus::NotFound;
        return false;
    }
    const std::size_t count = wire_->requestFrom(
        static_cast<int>(hardware::RTC_ADDRESS), 7, static_cast<int>(true));
    if (count != 7 || wire_->available() < 7) {
        present_ = true;
        status_ = RTCStatus::IoError;
        while (wire_->available()) (void)wire_->read();
        return false;
    }
    uint8_t registers[7]{};
    for (uint8_t& value : registers) value = static_cast<uint8_t>(wire_->read());
    present_ = true;
    if ((registers[0] & 0x80U) != 0) {
        status_ = RTCStatus::OscillatorStopped;
        return false;
    }

    const uint8_t secondBcd = registers[0] & 0x7FU;
    const uint8_t minuteBcd = registers[1] & 0x7FU;
    const uint8_t dateBcd = registers[4] & 0x3FU;
    const uint8_t monthBcd = registers[5] & 0x1FU;
    const uint8_t yearBcd = registers[6];
    if (!validBcd(secondBcd) || !validBcd(minuteBcd) ||
        !validBcd(dateBcd) || !validBcd(monthBcd) || !validBcd(yearBcd)) {
        status_ = RTCStatus::InvalidBcd;
        return false;
    }

    CalendarTime calendar;
    calendar.second = fromBcd(secondBcd);
    calendar.minute = fromBcd(minuteBcd);
    calendar.weekday = registers[3] & 0x07U;
    calendar.day = fromBcd(dateBcd);
    calendar.month = fromBcd(monthBcd);
    calendar.year = static_cast<uint16_t>(2000U + fromBcd(yearBcd));

    const uint8_t hourRegister = registers[2];
    if ((hourRegister & 0x40U) != 0) {
        const uint8_t hourBcd = hourRegister & 0x1FU;
        if (!validBcd(hourBcd)) {
            status_ = RTCStatus::InvalidBcd;
            return false;
        }
        const uint8_t hour12 = fromBcd(hourBcd);
        if (hour12 < 1 || hour12 > 12) {
            status_ = RTCStatus::InvalidCalendar;
            return false;
        }
        const bool pm = (hourRegister & 0x20U) != 0;
        calendar.hour = static_cast<uint8_t>((hour12 % 12U) + (pm ? 12U : 0U));
    } else {
        const uint8_t hourBcd = hourRegister & 0x3FU;
        if (!validBcd(hourBcd)) {
            status_ = RTCStatus::InvalidBcd;
            return false;
        }
        calendar.hour = fromBcd(hourBcd);
    }

    uint64_t unixTime = 0;
    if (!TimeUtils::valid(calendar, 2000, 2099) ||
        !TimeUtils::toUnix(calendar, unixTime)) {
        status_ = RTCStatus::InvalidCalendar;
        return false;
    }
    baseUnix_ = unixTime;
    baseMillis_ = millis();
    status_ = RTCStatus::Ready;
    return true;
}

bool RTC::now(uint64_t& unixTime) const {
    if (!valid()) return false;
    unixTime = baseUnix_ + static_cast<uint32_t>(millis() - baseMillis_) / 1000U;
    return true;
}

bool RTC::setUnix(uint64_t unixTime) {
    if (wire_ == nullptr) return false;
    CalendarTime calendar;
    if (!TimeUtils::fromUnix(unixTime, calendar) || calendar.year < 2000 ||
        calendar.year > 2099) {
        status_ = RTCStatus::InvalidCalendar;
        return false;
    }
    wire_->beginTransmission(hardware::RTC_ADDRESS);
    wire_->write(static_cast<uint8_t>(0));
    wire_->write(toBcd(calendar.second));  // CH=0 starts the oscillator.
    wire_->write(toBcd(calendar.minute));
    wire_->write(toBcd(calendar.hour));    // 24-hour mode.
    wire_->write(calendar.weekday);
    wire_->write(toBcd(calendar.day));
    wire_->write(toBcd(calendar.month));
    wire_->write(toBcd(static_cast<uint8_t>(calendar.year - 2000U)));
    if (wire_->endTransmission(true) != 0) {
        status_ = RTCStatus::IoError;
        return false;
    }
    delay(5);
    return read();
}

const char* RTC::statusText() const {
    switch (status_) {
        case RTCStatus::NotInitialized:
            return "not initialized";
        case RTCStatus::Ready:
            return "ready";
        case RTCStatus::NotFound:
            return "not found";
        case RTCStatus::OscillatorStopped:
            return "oscillator stopped";
        case RTCStatus::InvalidBcd:
            return "invalid BCD";
        case RTCStatus::InvalidCalendar:
            return "invalid calendar";
        case RTCStatus::IoError:
            return "I2C error";
    }
    return "unknown";
}

bool RTC::validBcd(uint8_t value) {
    return (value & 0x0FU) <= 9U && ((value >> 4U) & 0x0FU) <= 9U;
}

uint8_t RTC::fromBcd(uint8_t value) {
    return static_cast<uint8_t>((value >> 4U) * 10U + (value & 0x0FU));
}

uint8_t RTC::toBcd(uint8_t value) {
    return static_cast<uint8_t>((value / 10U) << 4U | (value % 10U));
}

}  // namespace vaultkey
