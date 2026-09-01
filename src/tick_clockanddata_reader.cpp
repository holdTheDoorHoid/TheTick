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

#ifdef USE_CLOCKANDDATA

#include "tick_clockanddata_reader.h"

#include "tick_board.h"
#include "tick_capture.h"
#include "tick_default_config.h"
#include "tick_utils.h"

// Module-owned settings.
static int pulse_width_us = 300;

// The clock and data lines are the same two physical wires as Wiegand D0/D1,
// so they come from the shared pin block rather than being configured twice.
static int pin_clock(void) { return tick_pin.d0; }
static int pin_data(void) { return tick_pin.d1; }

static tick_capture_buffer capture;
static bool attached = false;
static bool jamming = false;

// Debounce: ignore clock edges closer together than this.
static const uint32_t MIN_EDGE_GAP_US = 500;
// A card ends when the clock has been idle this long.
static const uint32_t FRAME_GAP_US = 5000;

static volatile uint32_t last_edge_us = 0;

static void IRAM_ATTR clockanddata_isr(void) {
  uint32_t now = micros();

  // The first edge after an idle period has no predecessor to debounce
  // against, so last_edge_us starting at zero would reject it on a device
  // whose micros() has just wrapped. Comparing the difference handles the
  // wrap correctly because both are uint32_t.
  if ((uint32_t)(now - last_edge_us) >= MIN_EDGE_GAP_US) {
    // Data is active low.
    tick_capture_push(&capture, digitalRead(pin_data()) == HIGH ? 0 : 1);
  }

  last_edge_us = now;
}

static void clockanddata_attach(void) {
  if (attached || jamming) return;
  attachInterrupt(digitalPinToInterrupt(pin_clock()), clockanddata_isr,
                  FALLING);
  attached = true;
}

static void clockanddata_detach(void) {
  if (!attached) return;
  detachInterrupt(digitalPinToInterrupt(pin_clock()));
  attached = false;
}

static void clockanddata_loop(void) {
  tick_capture_buffer frame;

  // One bit is the minimum a frame can carry; the gap is what actually
  // delimits it.
  if (!tick_capture_take(&capture, &frame, 1, FRAME_GAP_US)) return;

  char bits[TICK_MAX_BITS + 1];
  tick_capture_to_binary(&frame, bits, sizeof(bits));

  if (frame.overflowed) {
    append_log("clockanddata", String("truncated read, over ") + TICK_MAX_BITS +
                                  " bits on the line");
  }

  card_read_handler(String(bits) + ":" + String(frame.count));
}

static void clockanddata_jam_on(void) {
  if (jamming) return;
  clockanddata_detach();
  digitalWrite(pin_clock(), LOW);
  pinMode(pin_clock(), OUTPUT);
  jamming = true;
}

static void clockanddata_jam_off(void) {
  if (!jamming) return;
  pinMode(pin_clock(), INPUT_PULLUP);
  jamming = false;
  clockanddata_attach();
}

static void clockanddata_tx(const char *bitstream, size_t len,
                            unsigned long bits) {
  bool was_attached = attached;
  clockanddata_detach();

  output_debug_string(String("Sending data: ") + bitstream + ":" +
                      String(bits));

  // Never read past the string we were given, whatever bit count was asked
  // for. The caller validates too, but this is the loop that would run off
  // the end.
  if (bits > len) bits = len;

  for (unsigned long i = 0; i < bits; i++) {
    if (bitstream[i] == '1') {
      digitalWrite(pin_data(), LOW);
      pinMode(pin_data(), OUTPUT);
    }
    delayMicroseconds(pulse_width_us);

    digitalWrite(pin_clock(), LOW);
    pinMode(pin_clock(), OUTPUT);
    delayMicroseconds(pulse_width_us);
    pinMode(pin_clock(), INPUT_PULLUP);
    delayMicroseconds(pulse_width_us);

    pinMode(pin_data(), INPUT_PULLUP);
  }

  if (was_attached) clockanddata_attach();
}

static void clockanddata_configure(SPIFFSIniFile &ini, char *buffer,
                                   size_t buffer_len) {
  int value = 0;
  if (ini.getValue("clockanddata", "pulse_width", buffer, buffer_len, value)) {
    pulse_width_us = value;
  }
}

static bool clockanddata_init(void) {
  if (!tick_pin_is_valid_output(pin_clock()) ||
      !tick_pin_is_valid_output(pin_data())) {
    output_debug_string(F("Clock&data: pins not usable on this board"));
    return false;
  }

  tick_capture_reset(&capture);
  last_edge_us = micros();

  pinMode(pin_clock(), INPUT_PULLUP);
  pinMode(pin_data(), INPUT_PULLUP);
  return true;
}

const tick_protocol tick_protocol_clockanddata = {
    .name = "clockanddata",
    .short_name = "C&D",
    .ui_page = "/clockanddata.html",
    .configure = clockanddata_configure,
    .init = clockanddata_init,
    .attach = clockanddata_attach,
    .detach = clockanddata_detach,
    .loop = clockanddata_loop,
    .tx = clockanddata_tx,
    .jam_on = clockanddata_jam_on,
    .jam_off = clockanddata_jam_off,
};

#endif
