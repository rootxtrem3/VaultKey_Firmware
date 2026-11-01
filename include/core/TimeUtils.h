#pragma once

#include <cstdint>

namespace vaultkey {

struct CalendarTime {
    uint16_t year = 2000;
    uint8_t month = 1;
    uint8_t day = 1;
    uint8_t weekday = 7;  // DS1307 convention: 1=Sunday ... 7=Saturday
    uint8_t hour = 0;
    uint8_t minute = 0;
    uint8_t second = 0;
};

class TimeUtils {
  public:
    static bool isLeapYear(uint16_t year);
    static uint8_t daysInMonth(uint16_t year, uint8_t month);
    static bool valid(const CalendarTime& time, uint16_t minYear = 1970,
                      uint16_t maxYear = 2099);
    static bool toUnix(const CalendarTime& time, uint64_t& unixTime);
    static bool fromUnix(uint64_t unixTime, CalendarTime& time);
    static uint8_t weekday(uint16_t year, uint8_t month, uint8_t day);
};

}  // namespace vaultkey
