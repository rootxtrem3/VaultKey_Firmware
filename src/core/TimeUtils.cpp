#include "core/TimeUtils.h"

#include <limits>

namespace vaultkey {
namespace {

// Howard Hinnant's civil-calendar algorithms, adapted to fixed-width types.
int64_t daysFromCivil(int64_t year, unsigned month, unsigned day) {
    year -= month <= 2;
    const int64_t era = (year >= 0 ? year : year - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(year - era * 400);
    const unsigned doy =
        (153U * (month + (month > 2 ? static_cast<unsigned>(-3) : 9U)) + 2U) /
            5U +
        day - 1U;
    const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

void civilFromDays(int64_t days, int64_t& year, unsigned& month,
                   unsigned& day) {
    days += 719468;
    const int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(days - era * 146097);
    const unsigned yoe =
        (doe - doe / 1460U + doe / 36524U - doe / 146096U) / 365U;
    year = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365U * yoe + yoe / 4U - yoe / 100U);
    const unsigned mp = (5U * doy + 2U) / 153U;
    day = doy - (153U * mp + 2U) / 5U + 1U;
    month = mp + (mp < 10U ? 3U : static_cast<unsigned>(-9));
    year += month <= 2U;
}

}  // namespace

bool TimeUtils::isLeapYear(uint16_t year) {
    return (year % 4U == 0U && year % 100U != 0U) || year % 400U == 0U;
}

uint8_t TimeUtils::daysInMonth(uint16_t year, uint8_t month) {
    static constexpr uint8_t days[] = {31, 28, 31, 30, 31, 30,
                                       31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12) {
        return 0;
    }
    if (month == 2 && isLeapYear(year)) {
        return 29;
    }
    return days[month - 1];
}

bool TimeUtils::valid(const CalendarTime& time, uint16_t minYear,
                      uint16_t maxYear) {
    return time.year >= minYear && time.year <= maxYear && time.month >= 1 &&
           time.month <= 12 && time.day >= 1 &&
           time.day <= daysInMonth(time.year, time.month) && time.hour <= 23 &&
           time.minute <= 59 && time.second <= 59 && time.weekday >= 1 &&
           time.weekday <= 7;
}

bool TimeUtils::toUnix(const CalendarTime& time, uint64_t& unixTime) {
    if (!valid(time)) {
        return false;
    }
    const int64_t days = daysFromCivil(time.year, time.month, time.day);
    if (days < 0) {
        return false;
    }
    const uint64_t daySeconds = static_cast<uint64_t>(days) * 86400ULL;
    const uint64_t seconds = static_cast<uint64_t>(time.hour) * 3600ULL +
                             static_cast<uint64_t>(time.minute) * 60ULL +
                             time.second;
    if (daySeconds > std::numeric_limits<uint64_t>::max() - seconds) {
        return false;
    }
    unixTime = daySeconds + seconds;
    return true;
}

bool TimeUtils::fromUnix(uint64_t unixTime, CalendarTime& time) {
    const uint64_t days = unixTime / 86400ULL;
    if (days > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        return false;
    }
    int64_t year = 0;
    unsigned month = 0;
    unsigned day = 0;
    civilFromDays(static_cast<int64_t>(days), year, month, day);
    if (year < 1970 || year > 65535) {
        return false;
    }
    const uint32_t seconds = static_cast<uint32_t>(unixTime % 86400ULL);
    time.year = static_cast<uint16_t>(year);
    time.month = static_cast<uint8_t>(month);
    time.day = static_cast<uint8_t>(day);
    time.hour = static_cast<uint8_t>(seconds / 3600U);
    time.minute = static_cast<uint8_t>((seconds % 3600U) / 60U);
    time.second = static_cast<uint8_t>(seconds % 60U);
    time.weekday = weekday(time.year, time.month, time.day);
    return true;
}

uint8_t TimeUtils::weekday(uint16_t year, uint8_t month, uint8_t day) {
    const int64_t days = daysFromCivil(year, month, day);
    int64_t zeroBased = (days + 4) % 7;  // 1970-01-01 was Thursday.
    if (zeroBased < 0) {
        zeroBased += 7;
    }
    return static_cast<uint8_t>(zeroBased + 1);  // Sunday=1
}

}  // namespace vaultkey
