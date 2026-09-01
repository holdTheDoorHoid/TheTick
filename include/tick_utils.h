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

#ifndef TICK_UTILS_H
#define TICK_UTILS_H
#include "tick_default_config.h"
#include <cstddef>
#include <Arduino.h>

void output_debug_string(String s);
byte hex_to_byte(char in);
char c2h(unsigned char c);
uint32_t getChipID();
uint32_t readVDCVoltage(void);
void jamming_enable(void);
void jamming_disable(void);
void append_log(String facility, String text);
void card_read_handler(String s);
void clear_config(void);
extern String dhcp_hostname;

int getBootCount();

#endif