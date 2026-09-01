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

#include "tick_protocol.h"

#include <string.h>

#include "tick_clockanddata_reader.h"
#include "tick_osdp.h"
#include "tick_osdp_monitor.h"
#include "tick_wiegand_reader.h"

// The mode that does nothing. Having a real driver here rather than a null
// pointer means every call site can go straight through tick_current without
// checking, and an unconfigured device behaves predictably instead of falling
// into whichever switch case had no default.
const tick_protocol tick_protocol_disabled = {
    .name = "disabled",
    .short_name = "off",
    .ui_page = NULL,
    .configure = NULL,
    .init = NULL,
    .attach = NULL,
    .detach = NULL,
    .loop = NULL,
    .tx = NULL,
    .jam_on = NULL,
    .jam_off = NULL,
};

// The registry.
//
// This is the one place a new wire protocol has to be mentioned. Two forks
// adding a driver each touch adjacent lines here and nothing else, which is a
// trivial merge - the previous arrangement had them both rewriting nine
// switch statements spread over three files.
const tick_protocol *const tick_protocol_registry[] = {
    &tick_protocol_disabled,
#ifdef USE_WIEGAND
    &tick_protocol_wiegand,
#endif
#ifdef USE_CLOCKANDDATA
    &tick_protocol_clockanddata,
#endif
#ifdef USE_OSDP
    &tick_protocol_osdp_pd,
    &tick_protocol_osdp_cp,
#endif
#ifdef USE_OSDP_MONITOR
    &tick_protocol_osdp_monitor,
#endif
};

const size_t tick_protocol_registry_count =
    sizeof(tick_protocol_registry) / sizeof(tick_protocol_registry[0]);

const tick_protocol *tick_current = &tick_protocol_disabled;

const tick_protocol *tick_protocol_find(const char *name) {
  if (name == NULL || name[0] == '\0') return NULL;

  for (size_t i = 0; i < tick_protocol_registry_count; i++) {
    if (strcasecmp(tick_protocol_registry[i]->name, name) == 0) {
      return tick_protocol_registry[i];
    }
  }
  return NULL;
}

void tick_protocol_select(const tick_protocol *proto) {
  tick_current = proto ? proto : &tick_protocol_disabled;
}
