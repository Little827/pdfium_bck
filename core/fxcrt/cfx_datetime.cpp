// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_datetime.h"

#include "build/build_config.h"
#include "core/fxcrt/fx_system.h"
#include "third_party/base/check.h"

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || \
    BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_FUCHSIA) || defined(OS_ASMJS)
#include <sys/time.h>
#include <time.h>
#endif

#if BUILDFLAG(IS_FUCHSIA)
#include <limits>

#include "third_party/icu/source/i18n/unicode/calendar.h"  // nogncheck
#include "third_party/icu/source/i18n/unicode/gregocal.h"  // nogncheck
#endif

namespace {

constexpr uint8_t kDaysPerMonth[12] = {31, 28, 31, 30, 31, 30,
                                       31, 31, 30, 31, 30, 31};
constexpr uint8_t kDaysPerLeapMonth[12] = {31, 29, 31, 30, 31, 30,
                                           31, 31, 30, 31, 30, 31};
constexpr int32_t kDaysBeforeMonth[12] = {0,   31,  59,  90,  120, 151,
                                          181, 212, 243, 273, 304, 334};
constexpr int32_t kDaysBeforeLeapMonth[12] = {0,   31,  60,  91,  121, 152,
                                              182, 213, 244, 274, 305, 335};
constexpr int32_t kDaysPerYear = 365;
constexpr int32_t kDaysPerLeapYear = 366;
constexpr int32_t kMillisecondsPerDay = 86400000;

int32_t DaysBeforeMonthInYear(int32_t iYear, uint8_t iMonth) {
  DCHECK(iYear != 0);
  DCHECK(iMonth >= 1);
  DCHECK(iMonth <= 12);

  const int32_t* p =
      FX_IsLeapYear(iYear) ? kDaysBeforeLeapMonth : kDaysBeforeMonth;
  return p[iMonth - 1];
}

int32_t DaysInYear(int32_t iYear) {
  DCHECK(iYear != 0);
  return FX_IsLeapYear(iYear) ? kDaysPerLeapYear : kDaysPerYear;
}

int64_t DateToDays(int32_t iYear,
                   uint8_t iMonth,
                   uint8_t iDay,
                   bool bIncludeThisDay) {
  DCHECK(iYear != 0);
  DCHECK(iMonth >= 1);
  DCHECK(iMonth <= 12);
  DCHECK(iDay >= 1);
  DCHECK(iDay <= FX_DaysInMonth(iYear, iMonth));

  int64_t iDays = DaysBeforeMonthInYear(iYear, iMonth);
  iDays += iDay;
  if (!bIncludeThisDay)
    iDays--;

  if (iYear > 0) {
    iYear--;
  } else {
    iDays -= DaysInYear(iYear);
    iYear++;
  }
  return iDays + static_cast<int64_t>(iYear) * 365 + iYear / 4 - iYear / 100 +
         iYear / 400;
}

// Exact same structure as Win32 SYSTEMTIME.
struct FX_SYSTEMTIME {
  uint16_t wYear;
  uint16_t wMonth;
  uint16_t wDayOfWeek;
  uint16_t wDay;
  uint16_t wHour;
  uint16_t wMinute;
  uint16_t wSecond;
  uint16_t wMillisecond;
};

#if BUILDFLAG(IS_FUCHSIA)
// Explodes `millis_since_unix_epoch` using an icu::Calendar. Returns true if
// the conversion was successful.
bool ExplodeUsingIcuCalendar(int64_t millis_since_unix_epoch,
                             FX_SYSTEMTIME* exploded) {
  // ICU's year calculation is wrong for years too far in the past (though
  // other fields seem to be correct). Given that Windows datetime code only
  // works for values on/after 1601-01-01 00:00:00 UTC, just use that as a
  // reasonable lower-bound here as well.
  constexpr int64_t kInputLowerBound = 11644473600000;

  // FX_SYSTEMTIME's `wYear` field has an upper limit, just like Windows
  // datetime code. Use a rough approximation of this as the upper bound.
  constexpr int64_t kInputUpperBound =
      (static_cast<int64_t>(std::numeric_limits<uint16_t>::max()) - 1970) *
      kDaysPerYear * kMillisecondsPerDay;

  if (millis_since_unix_epoch < kInputLowerBound ||
      millis_since_unix_epoch > kInputUpperBound) {
    return false;
  }

  UErrorCode status = U_ZERO_ERROR;
  icu::GregorianCalendar calendar(*icu::TimeZone::getGMT(),
                                  icu::Locale::getUS(), status);
  if (!U_SUCCESS(status))
    return false;

  calendar.setTime(millis_since_unix_epoch, status);
  if (!U_SUCCESS(status))
    return false;

  bool got_all_fields = true;
  exploded->wYear = calendar.get(UCAL_YEAR, status);
  got_all_fields &= !!U_SUCCESS(status);
  // ICU's UCalendarMonths is 0-based. E.g., 0 for January.
  exploded->wMonth = calendar.get(UCAL_MONTH, status) + 1;
  got_all_fields &= !!U_SUCCESS(status);
  // ICU's UCalendarDaysOfWeek is 1-based. E.g., 1 for Sunday.
  exploded->wDayOfWeek = calendar.get(UCAL_DAY_OF_WEEK, status) - 1;
  got_all_fields &= !!U_SUCCESS(status);
  exploded->wDay = calendar.get(UCAL_DAY_OF_MONTH, status);
  got_all_fields &= !!U_SUCCESS(status);
  exploded->wHour = calendar.get(UCAL_HOUR_OF_DAY, status);
  got_all_fields &= !!U_SUCCESS(status);
  exploded->wMinute = calendar.get(UCAL_MINUTE, status);
  got_all_fields &= !!U_SUCCESS(status);
  exploded->wSecond = calendar.get(UCAL_SECOND, status);
  got_all_fields &= !!U_SUCCESS(status);
  exploded->wMillisecond = calendar.get(UCAL_MILLISECOND, status);
  got_all_fields &= !!U_SUCCESS(status);
  return got_all_fields;
}
#endif  // BUILDFLAG(IS_FUCHSIA)

}  // namespace

uint8_t FX_DaysInMonth(int32_t iYear, uint8_t iMonth) {
  DCHECK(iYear != 0);
  DCHECK(iMonth >= 1);
  DCHECK(iMonth <= 12);

  const uint8_t* p = FX_IsLeapYear(iYear) ? kDaysPerLeapMonth : kDaysPerMonth;
  return p[iMonth - 1];
}

bool FX_IsLeapYear(int32_t iYear) {
  DCHECK(iYear != 0);
  return ((iYear % 4) == 0 && (iYear % 100) != 0) || (iYear % 400) == 0;
}

// static
CFX_DateTime CFX_DateTime::Now() {
  FX_SYSTEMTIME local_time;
#if BUILDFLAG(IS_WIN)
  ::GetLocalTime(reinterpret_cast<LPSYSTEMTIME>(&local_time));
#elif BUILDFLAG(IS_FUCHSIA)
  timespec ts;
  int status = timespec_get(&ts, TIME_UTC);
  CHECK(status != 0);
  int64_t millis_since_unix_epoch = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  CHECK(ExplodeUsingIcuCalendar(millis_since_unix_epoch, &local_time));
#else
  timeval tv;
  gettimeofday(&tv, nullptr);

  struct tm st;
  localtime_r(&tv.tv_sec, &st);
  local_time.wYear = st.tm_year + 1900;
  local_time.wMonth = st.tm_mon + 1;
  local_time.wDayOfWeek = st.tm_wday;
  local_time.wDay = st.tm_mday;
  local_time.wHour = st.tm_hour;
  local_time.wMinute = st.tm_min;
  local_time.wSecond = st.tm_sec;
  local_time.wMillisecond = tv.tv_usec / 1000;
#endif  // BUILDFLAG(IS_WIN)

  return CFX_DateTime(local_time.wYear, static_cast<uint8_t>(local_time.wMonth),
                      static_cast<uint8_t>(local_time.wDay),
                      static_cast<uint8_t>(local_time.wHour),
                      static_cast<uint8_t>(local_time.wMinute),
                      static_cast<uint8_t>(local_time.wSecond),
                      local_time.wMillisecond);
}

int32_t CFX_DateTime::GetDayOfWeek() const {
  int32_t v = static_cast<int32_t>(DateToDays(year_, month_, day_, true) % 7);
  if (v < 0)
    v += 7;
  return v;
}

bool CFX_DateTime::operator==(const CFX_DateTime& other) const {
  return year_ == other.year_ && month_ == other.month_ && day_ == other.day_ &&
         hour_ == other.hour_ && minute_ == other.minute_ &&
         second_ == other.second_ && millisecond_ == other.millisecond_;
}
