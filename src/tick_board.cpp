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

#include "tick_board.h"

#include <soc/soc_caps.h>

#include "tick_utils.h"

// --- board table ------------------------------------------------------------
//
// One entry per supported board. Pick with a -D TICK_BOARD_* flag in
// platformio.ini. Keeping them side by side here makes the differences between
// chips visible, which is the point.
//
// vsense_factor is (R1 + R2) / R2 for the divider fitted to that revision:
// 120k/12k gives 11.0, 12k7/1k gives 13.7.

#if defined(TICK_BOARD_C3_SUPERMINI_REV02)

// ESP32-C3 SuperMini on Tick hardware revision 0.2. The shipping combination.
const tick_board TICK_BOARD = {
    .name = "c3-supermini-rev02",
    .pin_d0 = 0,
    .pin_d1 = 1,
    .pin_aux = 5,
    .pin_reset = 9,  // BOOT strapping pin on the C3
    .pin_vsense = 4,  // ADC1_CH4
    .vsense_factor = 11.0f,
    .osdp_pin_de = 7,
    .osdp_pin_re = 10,
    .osdp_pin_rx = 20,
    .osdp_pin_tx = 21,
    .osdp_pin_term = TICK_PIN_NONE,
    .osdp_uart = 1,
};

#elif defined(TICK_BOARD_C3_SUPERMINI_REV01)

// Tick hardware revision 0.1: same module, no dedicated I2C connector and a
// terminator jumper rather than a driven pin.
const tick_board TICK_BOARD = {
    .name = "c3-supermini-rev01",
    .pin_d0 = 0,
    .pin_d1 = 1,
    .pin_aux = 5,
    .pin_reset = 9,
    .pin_vsense = 4,
    .vsense_factor = 13.7f,
    .osdp_pin_de = 7,
    .osdp_pin_re = 10,
    .osdp_pin_rx = 20,
    .osdp_pin_tx = 21,
    .osdp_pin_term = TICK_PIN_NONE,
    .osdp_uart = 1,
};

#elif defined(TICK_BOARD_S3_DEVKITC1)

// ESP32-S3 DevKitC-1, for bringing the firmware up on the S3 before a Tick
// PCB exists for it. These pin assignments are a safe starting point, not a
// board layout: they avoid the flash and PSRAM pins (26-32), the USB pins
// (19, 20), the UART0 console (43, 44) and the strapping pins (0 aside, 3,
// 45, 46). Confirm them against your own wiring before trusting a capture -
// tick_pin_checked() will reject anything unusable at boot, but it cannot
// tell you that a legal pin is the wrong one.
const tick_board TICK_BOARD = {
    .name = "s3-devkitc1",
    .pin_d0 = 4,
    .pin_d1 = 5,
    .pin_aux = 6,
    .pin_reset = 0,   // BOOT button on the DevKitC-1
    .pin_vsense = 7,  // ADC1_CH6
    .vsense_factor = 11.0f,
    .osdp_pin_de = 15,
    .osdp_pin_re = 16,
    .osdp_pin_rx = 17,
    .osdp_pin_tx = 18,
    .osdp_pin_term = TICK_PIN_NONE,
    .osdp_uart = 1,
};

#else
#error "No board selected. Define one of TICK_BOARD_* in platformio.ini."
#endif

// --- pin validation ---------------------------------------------------------

tick_chip tick_chip_current(void) {
#if defined(CONFIG_IDF_TARGET_ESP32C3)
  return TICK_CHIP_ESP32C3;
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
  return TICK_CHIP_ESP32S3;
#elif defined(CONFIG_IDF_TARGET_ESP32C5)
  return TICK_CHIP_ESP32C5;
#else
  return TICK_CHIP_UNKNOWN;
#endif
}

int tick_chip_pin_count(tick_chip chip) {
  switch (chip) {
    case TICK_CHIP_ESP32C3:
      return 22;  // GPIO0..21
    case TICK_CHIP_ESP32S3:
      return 49;  // GPIO0..48
    case TICK_CHIP_ESP32C5:
      return 29;  // GPIO0..28
    default:
      return 0;
  }
}

bool tick_pin_reserved_on(tick_chip chip, int pin) {
  switch (chip) {
    case TICK_CHIP_ESP32C3:
      // 11..17 are the SPI flash interface. 18/19 are USB D-/D+, which the
      // console runs over on every board this firmware targets.
      if (pin >= 11 && pin <= 17) return true;
      if (pin == 18 || pin == 19) return true;
      return false;
    case TICK_CHIP_ESP32S3:
      // 26..32 are SPI flash and PSRAM. 33..37 are additionally taken on
      // modules with octal PSRAM, which is most of them, so they are treated
      // as reserved rather than left as a trap. 19/20 are USB D-/D+.
      if (pin >= 26 && pin <= 32) return true;
      if (pin >= 33 && pin <= 37) return true;
      if (pin == 19 || pin == 20) return true;
      return false;
    case TICK_CHIP_ESP32C5:
      // 24..28 are the SPI flash interface. 13/14 are USB D-/D+.
      if (pin >= 24 && pin <= 28) return true;
      if (pin == 13 || pin == 14) return true;
      return false;
    default:
      return false;
  }
}

bool tick_pin_is_adc1_on(tick_chip chip, int pin) {
  switch (chip) {
    case TICK_CHIP_ESP32C3:
      return pin >= 0 && pin <= 4;
    case TICK_CHIP_ESP32S3:
      return pin >= 1 && pin <= 10;
    case TICK_CHIP_ESP32C5:
      return pin >= 1 && pin <= 6;
    default:
      // Unknown chip: do not claim to know, and do not block the operator.
      return true;
  }
}

bool tick_pin_is_valid(int pin) {
  if (pin < 0 || pin >= SOC_GPIO_PIN_COUNT) return false;
  if (!GPIO_IS_VALID_GPIO(pin)) return false;
  if (tick_pin_reserved_on(tick_chip_current(), pin)) return false;
  return true;
}

bool tick_pin_is_valid_output(int pin) {
  if (!tick_pin_is_valid(pin)) return false;
  return GPIO_IS_VALID_OUTPUT_GPIO(pin);
}

bool tick_pin_is_adc1(int pin) {
  return tick_pin_is_adc1_on(tick_chip_current(), pin);
}

int tick_pin_checked(const char *what, int configured, int fallback,
                     bool needs_output) {
  if (configured == TICK_PIN_NONE) return TICK_PIN_NONE;

  bool ok = needs_output ? tick_pin_is_valid_output(configured)
                         : tick_pin_is_valid(configured);
  if (ok) return configured;

  // Loud, because a bad pin here means the device looks dead in a wall.
  output_debug_string(String("Bad pin for ") + what + ": " + configured);
  append_log("config", String("rejected pin ") + configured + " for " + what +
                           ", using " + fallback);
  return fallback;
}
