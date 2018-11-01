// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef FXJS_FX_DATE_HELPERS_H_
#define FXJS_FX_DATE_HELPERS_H_

double FX_GetDateTime();
int FX_GetYearFromTime(double dt);
int FX_GetMonthFromTime(double dt);
int FX_GetDayFromTime(double dt);
int FX_GetHourFromTime(double dt);
int FX_GetMinFromTime(double dt);
int FX_GetSecFromTime(double dt);
double FX_LocalTime(double d);
double FX_MakeDay(int nYear, int nMonth, int nDay);
double FX_MakeTime(int nHour, int nMin, int nSec, int nMs);
double FX_MakeDate(double day, double time);

#endif  // FXJS_FX_DATE_HELPERS_H_
