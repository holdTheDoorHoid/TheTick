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

#ifndef TICK_CAPTURE_H
#define TICK_CAPTURE_H

#include <Arduino.h>

#include <stddef.h>
#include <stdint.h>

// Bounded, allocation-free capture buffer shared by the bit-oriented wire
// protocols.
//
// Interrupt handlers call tick_capture_push() to add one bit; the main loop
// calls tick_capture_take() to lift a complete frame out. Nothing here
// allocates, so it is safe to run from an ISR - the previous implementation
// grew an Arduino String from inside the interrupt, which both called the
// heap in interrupt context and had no upper bound on how much a noisy
// reader line could consume.
//
// 512 bits is far more than any real credential (the longest formats in the
// wild are under 200) and matches libosdp's 64-byte card data limit exactly,
// so a captured frame can always be handed to OSDP without truncation.

#define TICK_MAX_BITS 512
#define TICK_MAX_BYTES (TICK_MAX_BITS / 8)
// ceil(TICK_MAX_BITS / 4) hex digits, plus NUL.
#define TICK_MAX_HEX (TICK_MAX_BITS / 4)
// Longest transmit payload in characters. Wiegand encodes four bits per hex
// digit, but clock&data sends one character per bit, so the worst case is one
// character per bit and not one per nibble.
#define TICK_TX_MAX_CHARS TICK_MAX_BITS

struct tick_capture_buffer {
  uint8_t bits[TICK_MAX_BYTES];  // MSB-first, bit 0 is the first bit received
  uint16_t count;                // bits held
  uint32_t last_bit_us;          // micros() of the most recent bit
  bool overflowed;               // more bits arrived than would fit
};

// Reset a buffer to empty. Main-loop context only.
void tick_capture_reset(tick_capture_buffer *buf);

// Append one bit. Safe to call from an interrupt handler: no allocation, no
// flash access, bounded work. Bits past TICK_MAX_BITS are dropped and the
// overflow flag is raised so the loop can log a truncated read rather than
// silently reporting a wrong credential.
void IRAM_ATTR tick_capture_push(tick_capture_buffer *buf, uint8_t value);

// If a frame is complete - at least `min_bits` held and no new bit for
// `gap_us` - copy it into `out` and empty the source buffer, returning true.
// The copy happens inside a short critical section; formatting and logging
// then happen on the caller's own copy with interrupts live, so the capture
// path is never blocked by a flash write or a display refresh.
bool tick_capture_take(tick_capture_buffer *buf, tick_capture_buffer *out,
                       uint16_t min_bits, uint32_t gap_us);

// Render a captured frame as the wire format the log and web UI expect.
// Both write at most `out_len` bytes including the NUL and return the number
// of characters written.

// Big-endian hex, ceil(count/4) digits, zero padded on the left - the format
// the Wiegand pages parse. Matches the output of the previous
// wiegand_fix_reader1_string() bit-shuffling, without the string surgery.
size_t tick_capture_to_hex(const tick_capture_buffer *buf, char *out,
                           size_t out_len);

// One '0' or '1' per bit - the format the clock&data page parses.
size_t tick_capture_to_binary(const tick_capture_buffer *buf, char *out,
                              size_t out_len);

// --- transmit queue ---------------------------------------------------------
//
// Replay requests arrive from three places on three different tasks: the web
// server, the BLE host task, and the main loop itself when a control card is
// seen. Bit-banging a waveform takes tens of milliseconds with interrupts
// detached, so letting two of them start at once corrupts both the waveform
// and the interrupt state.
//
// Everything therefore submits here and the main loop is the only thing that
// transmits. This is also the one place credential length is validated, which
// is what keeps an over-long value from running off the end of a driver's
// buffer.

// Queue a credential for transmission. Safe from any task. Returns false if
// the input is malformed, too long, or a transmission is already pending -
// callers should report that rather than assume it went out.
bool tick_tx_submit(const char *hex, unsigned long bits);

// Parse and queue the "<hex>:<bits>" form used by the HTTP and BLE
// interfaces. Returns false on anything it cannot parse.
bool tick_tx_submit_pair(const char *value);

// Send a pending request, if there is one. Main loop only.
void tick_tx_service(void);

#endif
