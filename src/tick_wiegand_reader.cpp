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

// This code is based on ESPKey, by Kenny McElroy
// https://github.com/octosavvi/ESPKey/blob/master/ESPKey.ino
// released under GNU General Public License version 2.

#ifdef USE_WIEGAND

#include "tick_wiegand_reader.h"

#include "tick_board.h"
#include "tick_capture.h"
#include "tick_default_config.h"
#include "tick_utils.h"

// Module-owned settings. These used to be globals declared in a shared header
// and parsed by a shared function that had to know about every module; now the
// only file that mentions them is this one.
static int pulse_width_us = 34;
static int pulse_gap_us = 1966;

static tick_capture_buffer capture;
static bool attached = false;
static bool jamming = false;

// A Wiegand frame ends when the line has been quiet for a few milliseconds.
static const uint32_t FRAME_GAP_US = 5000;

// --- capture ----------------------------------------------------------------

// Both data lines share one handler. Whichever line went low carries the bit:
// D0 is a zero, D1 is a one.
//
// This runs in interrupt context and does nothing but write into a fixed
// buffer. The previous version appended to an Arduino String here, which
// called the heap from an ISR and had no upper bound on how far a noisy line
// could grow it.
static void IRAM_ATTR wiegand_isr(void) {
  // tick_pin, not TICK_BOARD: the board table holds the defaults, but the
  // operator can move these lines in config.txt and the ISR has to read the
  // pins actually in use.
  if (digitalRead(tick_pin.d0) == LOW) {
    tick_capture_push(&capture, 0);
  }
  if (digitalRead(tick_pin.d1) == LOW) {
    tick_capture_push(&capture, 1);
  }
}

static void wiegand_attach(void) {
  if (attached || jamming) return;
  attachInterrupt(digitalPinToInterrupt(tick_pin.d0), wiegand_isr, FALLING);
  attachInterrupt(digitalPinToInterrupt(tick_pin.d1), wiegand_isr, FALLING);
  attached = true;
}

static void wiegand_detach(void) {
  if (!attached) return;
  detachInterrupt(digitalPinToInterrupt(tick_pin.d0));
  detachInterrupt(digitalPinToInterrupt(tick_pin.d1));
  attached = false;
}

static void wiegand_loop(void) {
  tick_capture_buffer frame;

  // Lift the frame out under a short lock, then do all the slow work -
  // formatting, the flash write, the display refresh - with interrupts live.
  // Previously the interrupts stayed detached across the log write and a full
  // OLED frame, roughly forty milliseconds during which a second badge was
  // simply lost.
  if (!tick_capture_take(&capture, &frame, CARD_LEN, FRAME_GAP_US)) return;

  char hex[TICK_MAX_HEX + 1];
  tick_capture_to_hex(&frame, hex, sizeof(hex));

  if (frame.overflowed) {
    append_log("wiegand", String("truncated read, over ") + TICK_MAX_BITS +
                              " bits on the line");
  }

  card_read_handler(String(hex) + ":" + String(frame.count));
}

// --- jamming ----------------------------------------------------------------

static void wiegand_jam_on(void) {
  if (jamming) return;
  wiegand_detach();
  // Latch low before enabling the driver so the pin never glitches high.
  digitalWrite(tick_pin.d0, LOW);
  pinMode(tick_pin.d0, OUTPUT);
  jamming = true;
}

static void wiegand_jam_off(void) {
  if (!jamming) return;
  // Wiegand is open collector: release the line and let the controller's
  // pull-up take it high. The internal pull-up only keeps the input from
  // floating on a bench board with nothing attached.
  pinMode(tick_pin.d0, INPUT_PULLUP);
  jamming = false;
  wiegand_attach();
}

// --- transmit ---------------------------------------------------------------

static void wiegand_assert_bit(uint8_t bit) {
  int pin = bit ? tick_pin.d1 : tick_pin.d0;
  digitalWrite(pin, LOW);
  pinMode(pin, OUTPUT);
  delayMicroseconds(pulse_width_us);
  pinMode(pin, INPUT_PULLUP);
  delayMicroseconds(pulse_gap_us);
}

static void wiegand_tx(const char *hex, size_t hex_len, unsigned long bits) {
  // Only ever reached from tick_tx_service() on the main loop, so this cannot
  // collide with another transmission or with the capture path.
  bool was_attached = attached;
  wiegand_detach();

  output_debug_string(String("Sending data: ") + hex + ":" + String(bits));

  unsigned long available = (unsigned long)hex_len * 4;
  unsigned long excess = 0;

  if (available > bits) {
    // More hex digits than bits asked for: drop whole leading nibbles, then
    // skip the remaining leading bits of the first nibble kept.
    excess = available - bits;
    hex += (excess / 4);
    hex_len -= (size_t)(excess / 4);
    excess %= 4;
  } else if (available < bits) {
    // Fewer digits than bits: pad with leading zeroes on the wire.
    for (unsigned long i = bits - available; i > 0; i--) {
      wiegand_assert_bit(0);
    }
  }

  for (size_t i = 0; i < hex_len; i++) {
    uint8_t nibble = hex_to_byte(hex[i]);
    for (int x = 3 - (int)excess; x >= 0; x--) {
      wiegand_assert_bit((nibble >> x) & 1);
    }
    excess = 0;
  }

  if (was_attached) wiegand_attach();
}

// --- lifecycle --------------------------------------------------------------

static void wiegand_configure(SPIFFSIniFile &ini, char *buffer,
                              size_t buffer_len) {
  int value = 0;
  if (ini.getValue("wiegand", "pulse_width", buffer, buffer_len, value)) {
    pulse_width_us = value;
  }
  if (ini.getValue("wiegand", "pulse_gap", buffer, buffer_len, value)) {
    pulse_gap_us = value;
  }
}

static bool wiegand_init(void) {
  if (!tick_pin_is_valid_output(tick_pin.d0) ||
      !tick_pin_is_valid_output(tick_pin.d1)) {
    output_debug_string(F("Wiegand: D0/D1 not usable on this board"));
    return false;
  }

  tick_capture_reset(&capture);

  pinMode(tick_pin.d0, INPUT_PULLUP);
  pinMode(tick_pin.d1, INPUT_PULLUP);
  return true;
}

const tick_protocol tick_protocol_wiegand = {
    .name = "wiegand",
    .short_name = "WGD",
    .ui_page = "/wiegand.html",
    .configure = wiegand_configure,
    .init = wiegand_init,
    .attach = wiegand_attach,
    .detach = wiegand_detach,
    .loop = wiegand_loop,
    .tx = wiegand_tx,
    .jam_on = wiegand_jam_on,
    .jam_off = wiegand_jam_off,
};

#endif
