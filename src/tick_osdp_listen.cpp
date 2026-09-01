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

#ifdef USE_OSDP_MONITOR

#include <Arduino.h>

#include "tick_board.h"
#include "tick_default_config.h"
#include "tick_osdp.h"
#include "tick_osdp_monitor.h"
#include "tick_protocol.h"
#include "tick_utils.h"

// Passive OSDP monitoring as a wire protocol driver.
//
// This mode never transmits. It brings the RS-485 transceiver up with the
// driver disabled and no TX pin handed to the UART, watches the conversation
// between a reader and its controller, and reports the conditions the
// published OSDP attacks depend on.
//
// It deliberately does not depend on libosdp. A device that only listens does
// not need a protocol stack, and keeping the dependency out means monitoring
// fits in a build that has no room for one.

static HardwareSerial *serial = NULL;
static osdp_monitor monitor;
static int baudrate = OSDP_BAUDRATE;

// Bytes that arrived but did not yet form a whole frame. A frame can be split
// across UART reads, and discarding the remainder would lose roughly one
// frame in every read.
static uint8_t carry[OSDP_MAX_FRAME];
static size_t carry_len = 0;

// Credentials seen in the clear are the finding an operator most wants in
// front of them, so they go to the card handler as well as the log.
static void report_threat(const osdp_threat_report *report, void *context) {
  (void)context;

  String line = String(osdp_threat_name(report->threat)) + " addr=" +
                String(report->address) + " frame=0x" +
                String(report->frame_id, HEX);
  append_log("osdp_threat", line);
  output_debug_string(String("OSDP: ") + osdp_threat_name(report->threat));
}

static void listen_configure(SPIFFSIniFile &ini, char *buffer,
                             size_t buffer_len) {
  int value = 0;
  if (ini.getValue("osdp", "baudrate", buffer, buffer_len, value)) {
    if (value == 9600 || value == 19200 || value == 38400 || value == 57600 ||
        value == 115200 || value == 230400) {
      baudrate = value;
    }
  }
}

static bool listen_init(void) {
  osdp_monitor_init(&monitor, report_threat, NULL);
  carry_len = 0;

  serial = osdp_listen_begin(baudrate);
  if (serial == NULL) return false;

  output_debug_string(String("OSDP monitor at ") + baudrate);
  return true;
}

static void listen_loop(void) {
  if (serial == NULL) return;

  // Top the carry buffer up from the UART, then hand the whole thing to the
  // monitor and keep whatever it could not yet use.
  while (serial->available() > 0 && carry_len < sizeof(carry)) {
    int c = serial->read();
    if (c < 0) break;
    carry[carry_len++] = (uint8_t)c;
  }

  if (carry_len == 0) return;

  size_t used = osdp_monitor_feed_bytes(&monitor, carry, carry_len);

  if (used >= carry_len) {
    carry_len = 0;
  } else if (used > 0) {
    memmove(carry, carry + used, carry_len - used);
    carry_len -= used;
  } else if (carry_len == sizeof(carry)) {
    // A full buffer that yielded nothing is noise, not a frame. Drop the
    // oldest half rather than wedging forever on a bus that is not OSDP.
    memmove(carry, carry + sizeof(carry) / 2, sizeof(carry) / 2);
    carry_len = sizeof(carry) / 2;
  }
}

const tick_protocol tick_protocol_osdp_monitor = {
    .name = "osdp_monitor",
    .short_name = "OSDP-MON",
    .ui_page = NULL,
    .configure = listen_configure,
    .init = listen_init,
    .attach = NULL,
    .detach = NULL,
    .loop = listen_loop,
    // Passive by construction: no transmit hook, and the UART was opened
    // without a TX pin.
    .tx = NULL,
    .jam_on = NULL,
    .jam_off = NULL,
};

// Read-only access for the web interface.
const osdp_monitor *osdp_monitor_state(void) { return &monitor; }

#endif
