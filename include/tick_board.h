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

#ifndef TICK_BOARD_H
#define TICK_BOARD_H

#include <Arduino.h>

#include <stdint.h>

// Board description and pin validation.
//
// Everything the firmware needs to know about the physical board lives in one
// table in tick_board.cpp, selected by a single -D TICK_BOARD_* flag. Adding a
// board means adding one entry there. Pin defaults used to be scattered
// through per-revision copies of pins_arduino.h, which is Arduino's file for
// describing the module's own pin mapping - two unrelated concerns in a file
// that had to be duplicated for every board x revision combination.
//
// The validation helpers matter more than they look. Pin numbers come from a
// text file the operator edits, and the set of legal pins differs sharply
// between chips: the C3 has 0-21 with 11-17 committed to flash, the S3 has
// 0-48 with 26-32 on flash and PSRAM, the C5 differs again. Moving a config
// file between chips without checking is how you end up driving a flash pin.

// Which ESP32 family this firmware is running on. Named explicitly so the
// per-chip pin rules can be expressed as data and tested for every chip from
// a single host build, rather than hiding behind preprocessor branches that
// only ever compile one way.
enum tick_chip {
  TICK_CHIP_UNKNOWN = 0,
  TICK_CHIP_ESP32C3,
  TICK_CHIP_ESP32S3,
  TICK_CHIP_ESP32C5,
};

// The chip this build targets.
tick_chip tick_chip_current(void);

// True if `pin` is committed to flash, PSRAM or USB on `chip` and must not be
// repurposed. Pure function of its arguments.
bool tick_pin_reserved_on(tick_chip chip, int pin);

// True if `pin` is on ADC1 for `chip`. ADC2 is unreadable while WiFi is up.
bool tick_pin_is_adc1_on(tick_chip chip, int pin);

// Highest GPIO number the chip exposes, exclusive.
int tick_chip_pin_count(tick_chip chip);

// Sentinel for "this board does not have that pin". Deliberately a signed
// type: the previous PIN_TERM_DEFAULT was a uint8_t holding -1, which became
// 255, so the `!= -1` guard was never false and the code configured GPIO 255.
#define TICK_PIN_NONE (-1)

struct tick_board {
  const char *name;

  // Reader interface. Wiegand D0/D1 double as the clock&data clock/data pair
  // on the same physical wires.
  int8_t pin_d0;
  int8_t pin_d1;

  // Housekeeping.
  int8_t pin_aux;
  int8_t pin_reset;
  int8_t pin_vsense;
  float vsense_factor;

  // RS-485 transceiver for OSDP.
  int8_t osdp_pin_de;
  int8_t osdp_pin_re;
  int8_t osdp_pin_rx;
  int8_t osdp_pin_tx;
  int8_t osdp_pin_term;  // TICK_PIN_NONE where no terminator is fitted
  // Which HardwareSerial drives the transceiver. The C3 has two general
  // purpose UARTs, the S3 three, and which one the USB console occupies
  // depends on the board, so this cannot be hardcoded to Serial1.
  uint8_t osdp_uart;
};

// The board this firmware was built for.
extern const tick_board TICK_BOARD;

// True if `pin` exists on this chip and is not committed to flash, PSRAM or
// USB. Accepts TICK_PIN_NONE as invalid - callers check for the sentinel
// separately when a missing pin is legitimate.
bool tick_pin_is_valid(int pin);

// As above, and also usable as an output. On some chips a few pins are
// input-only.
bool tick_pin_is_valid_output(int pin);

// True if `pin` is on ADC1. ADC2 cannot be read while WiFi is active, so a
// voltage sense pin on ADC2 returns garbage in normal operation.
bool tick_pin_is_adc1(int pin);

// Validate a configured pin, falling back to `fallback` and reporting the
// problem if it is unusable. `what` names the setting in the message.
// Returns the pin that should actually be used.
int tick_pin_checked(const char *what, int configured, int fallback,
                     bool needs_output);

#endif
