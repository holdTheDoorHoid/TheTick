// Copyright (C) 2024, 2025 Jakub "lenwe" Kramarz
// This file is part of The Tick.
//
// The Tick is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Tick is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License

#include <Preferences.h>

#include "tick_board.h"
#include "tick_findings.h"
#include "tick_utils.h"

int boot_count = 0;

byte hex_to_byte(char in) {
  if (in >= '0' && in <= '9')
    return in - '0';
  else if (in >= 'A' && in <= 'F')
    return in - 'A' + 10;
  else if (in >= 'a' && in <= 'f')
    return in - 'a' + 10;
  else
    return 0;
}

char c2h(unsigned char c) { return "0123456789abcdef"[0xF & c]; }

uint32_t getChipID() {
  uint32_t chipId = 0;
  for (int i = 0; i < 17; i = i + 8) {
    chipId |= ((ESP.getEfuseMac() >> (40 - i)) & 0xff) << i;
  }
  return chipId;
}

uint32_t readVDCVoltage(void) {
  // vsense_factor = ((R1 + R2) / R2)
  // for R1=120k and R2=12k, vsense_factor = 11.0
  // for R1=12k7 and R2=1k, vsense_factor = 13.7
  if (!tick_pin_is_valid(tick_pin.vsense)) return 0;
  int raw_mv = analogReadMilliVolts(tick_pin.vsense);
  float vdc = ((float)raw_mv) * vsense_factor;
  return (uint32_t)vdc;
}

void incrementBootCount() {
  Preferences preferences;
  preferences.begin("boot", false);
  boot_count = preferences.getInt("boot_count", 10) + 1;
  preferences.putInt("boot_count", boot_count);
  preferences.end();
}

int getBootCount() {
  if(boot_count == 0)
    incrementBootCount();
  return boot_count;
}

void tick_record_finding(const char *name, const char *detail, int severity,
                         bool has_address, uint8_t address) {
  tick_finding_record(&tick_global_findings, name, detail,
                      (tick_severity)severity, has_address, address, millis());
}

String dhcp_hostname;
