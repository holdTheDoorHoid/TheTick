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

#ifndef TICK_FINDINGS_H
#define TICK_FINDINGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Evidence store.
//
// The log records everything that happened; this records the things worth
// telling someone about. It is what leaves the device at the end of an
// engagement, so each entry has to stand on its own: what was found, when it
// was first seen, how often, against which peripheral, and the observed
// value that proves it.
//
// Kept free of Arduino dependencies - the timestamp is passed in - so the
// serialiser can be tested on the host, which matters when the output is a
// client deliverable.

#define TICK_FINDING_NAME_LEN 28
#define TICK_FINDING_DETAIL_LEN 72
#define TICK_MAX_FINDINGS 16

enum tick_severity {
  TICK_SEVERITY_INFO = 0,
  TICK_SEVERITY_LOW,
  TICK_SEVERITY_MEDIUM,
  TICK_SEVERITY_HIGH,
  TICK_SEVERITY_CRITICAL,
};

struct tick_finding {
  bool used;
  char name[TICK_FINDING_NAME_LEN];
  // The observed value that makes the finding checkable: a recovered key, a
  // captured credential, a capability byte.
  char detail[TICK_FINDING_DETAIL_LEN];
  tick_severity severity;
  uint8_t address;
  bool has_address;
  uint32_t first_ms;
  uint32_t last_ms;
  uint32_t count;
};

struct tick_findings {
  tick_finding items[TICK_MAX_FINDINGS];
  uint32_t dropped;  // findings that arrived with the store full
};

void tick_findings_init(tick_findings *store);

// Record a finding. Repeat findings of the same name update the count and
// last-seen time rather than adding a row, so the report stays readable after
// a device has been on a bus for a week.
//
// `detail` may be null. Anything unprintable in it is dropped, so a captured
// value cannot break the JSON it ends up in.
void tick_finding_record(tick_findings *store, const char *name,
                         const char *detail, tick_severity severity,
                         bool has_address, uint8_t address, uint32_t now_ms);

// Serialise to a JSON array. Returns the number of characters written,
// excluding the terminator, and always writes a valid document even when the
// buffer is too small to hold everything.
size_t tick_findings_to_json(const tick_findings *store, char *out,
                             size_t out_len);

const char *tick_severity_name(tick_severity severity);

// The device's evidence store. One per device, written by whichever mode is
// running and read by the web interface.
extern tick_findings tick_global_findings;

// Number of findings currently held.
size_t tick_findings_count(const tick_findings *store);

// Highest severity held, for an at-a-glance verdict.
tick_severity tick_findings_worst(const tick_findings *store);

#endif
