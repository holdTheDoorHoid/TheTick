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

#ifndef TICK_PROTOCOL_H
#define TICK_PROTOCOL_H

#include <Arduino.h>
#include <SPIFFSIniFile.h>

#include <stddef.h>

// Wire-protocol driver interface.
//
// Every wire protocol the Tick speaks - Wiegand, clock&data, OSDP PD, OSDP CP -
// is described by one instance of this struct, and the rest of the firmware
// talks to whichever one is selected through `tick_current`. Adding a protocol
// means writing one of these and adding it to the registry in tick_protocol.cpp;
// no other file needs to change.
//
// All function pointers are optional. A driver leaves out what it does not
// implement and the tick_proto_* helpers below turn the missing entries into
// no-ops. That also means a hook added here later does not break existing
// drivers - which is what keeps parallel forks mergeable.

struct tick_protocol {
  // Identity. `name` is what appears in config.txt as `[tick] mode=`, in log
  // lines as the facility, and in /version as the mode. Matching is
  // case-insensitive.
  const char *name;
  // Short label for the 128x32 OLED, where "clockanddata" does not fit.
  // Falls back to `name` when null.
  const char *short_name;
  // Landing page served for "/". Null means the generic dashboard.
  const char *ui_page;

  // Read this driver's own settings out of config.txt. Called for every
  // registered driver, selected or not, so that the web UI can report on
  // modes that are not currently active. `buffer`/`buffer_len` is the
  // scratch space SPIFFSIniFile needs for parsing.
  void (*configure)(SPIFFSIniFile &ini, char *buffer, size_t buffer_len);

  // Claim and configure the GPIO/peripherals this driver needs. Only ever
  // called on the selected driver, after configure() and after pin
  // validation. Return false to refuse the mode (bad pins, missing
  // hardware); the firmware then falls back to disabled rather than
  // running with a half-initialised peripheral.
  bool (*init)(void);

  // Start and stop capture. attach() must be safe to call when already
  // attached, detach() when already detached.
  void (*attach)(void);
  void (*detach)(void);

  // Called from the main loop, on the same task as everything else.
  void (*loop)(void);

  // Transmit a credential. `hex` is a NUL-terminated uppercase hex string of
  // `hex_len` characters, `bits` the wire bit count. Only ever called from
  // the main loop by way of tick_tx_service(), never directly from a
  // network or BLE callback - see tick_capture.h.
  void (*tx)(const char *hex, size_t hex_len, unsigned long bits);

  // Denial of service: hold the line so the reader cannot talk to the
  // controller, and release it again.
  void (*jam_on)(void);
  void (*jam_off)(void);
};

// The registry, in the order drivers are offered to the config file.
// Index 0 is always the disabled driver.
extern const tick_protocol *const tick_protocol_registry[];
extern const size_t tick_protocol_registry_count;

// The driver in force. Never null: it points at the disabled driver until
// something selects otherwise, so callers never need a null check.
extern const tick_protocol *tick_current;

// The do-nothing driver, used when no mode is configured or when a mode
// refused to initialise.
extern const tick_protocol tick_protocol_disabled;

// Select by name, case-insensitively. Returns null when no driver matches -
// which means either a typo in config.txt or a mode whose feature was not
// compiled into this build. Both deserve a message, so the caller reports it.
const tick_protocol *tick_protocol_find(const char *name);

// Point tick_current at `proto` (null selects the disabled driver).
void tick_protocol_select(const tick_protocol *proto);

// --- call-site helpers ------------------------------------------------------
// These exist so that an optional hook left out by a driver costs nothing at
// the call site, and so that the null checks live in exactly one place.

static inline const char *tick_proto_name(void) { return tick_current->name; }

static inline const char *tick_proto_short_name(void) {
  return tick_current->short_name ? tick_current->short_name
                                  : tick_current->name;
}

static inline void tick_proto_attach(void) {
  if (tick_current->attach) tick_current->attach();
}

static inline void tick_proto_detach(void) {
  if (tick_current->detach) tick_current->detach();
}

static inline void tick_proto_loop(void) {
  if (tick_current->loop) tick_current->loop();
}

static inline void tick_proto_jam_on(void) {
  if (tick_current->jam_on) tick_current->jam_on();
}

static inline void tick_proto_jam_off(void) {
  if (tick_current->jam_off) tick_current->jam_off();
}

static inline bool tick_proto_can_tx(void) { return tick_current->tx != NULL; }

#endif
