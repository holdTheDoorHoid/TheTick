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

#ifndef TICK_OSDP_H
#define TICK_OSDP_H

#include "tick_protocol.h"

// Read the RS-485 transceiver pin assignments. Always compiled, because the
// transceiver has to be parked in high impedance on every boot whether or not
// this build speaks OSDP.
void osdp_pins_configure(SPIFFSIniFile &ini, char *buffer, size_t buffer_len);

// Put the transceiver into high impedance with the receiver disabled.
void osdp_disable_transceiver(void);

// How many bytes of card data to copy into an OSDP card read event.
//
// The overflow this replaces came from sizing the copy as hex_len/2 with no
// limit, so a long value posted to /txid ran past a 64 byte buffer. Deriving
// the count from the declared bit length instead makes it inherently bounded
// - a credential can only be as long as the bit count says it is - and the
// remaining two clamps mean no combination of arguments can exceed the
// destination.
//
// Exposed here rather than kept private so it can be tested on the host.
static inline size_t osdp_cardread_bytes(size_t hex_len, unsigned long bits,
                                         size_t max_bytes) {
  size_t from_bits = (size_t)((bits + 7) / 8);
  size_t from_hex = hex_len / 2;
  size_t n = from_bits < from_hex ? from_bits : from_hex;
  return n > max_bytes ? max_bytes : n;
}

#ifdef USE_OSDP
extern const tick_protocol tick_protocol_osdp_pd;
extern const tick_protocol tick_protocol_osdp_cp;
#endif

#endif
