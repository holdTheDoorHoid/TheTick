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

#include "tick_capture.h"

#include <string.h>

#include "tick_protocol.h"
#include "tick_utils.h"

// One lock covers both the capture buffers and the transmit slot. They are
// only ever held for a handful of instructions - a memcpy of at most 64 bytes
// - so a single lock costs nothing and removes any chance of ordering bugs
// between two of them.
static portMUX_TYPE tick_capture_mux = portMUX_INITIALIZER_UNLOCKED;

void tick_capture_reset(tick_capture_buffer *buf) {
  portENTER_CRITICAL(&tick_capture_mux);
  buf->count = 0;
  buf->overflowed = false;
  buf->last_bit_us = 0;
  portEXIT_CRITICAL(&tick_capture_mux);
}

void IRAM_ATTR tick_capture_push(tick_capture_buffer *buf, uint8_t value) {
  portENTER_CRITICAL_ISR(&tick_capture_mux);
  uint16_t n = buf->count;
  if (n < TICK_MAX_BITS) {
    uint8_t mask = (uint8_t)(0x80u >> (n & 7));
    if (value) {
      buf->bits[n >> 3] |= mask;
    } else {
      buf->bits[n >> 3] &= (uint8_t)~mask;
    }
    buf->count = (uint16_t)(n + 1);
  } else {
    buf->overflowed = true;
  }
  buf->last_bit_us = micros();
  portEXIT_CRITICAL_ISR(&tick_capture_mux);
}

bool tick_capture_take(tick_capture_buffer *buf, tick_capture_buffer *out,
                       uint16_t min_bits, uint32_t gap_us) {
  bool taken = false;

  portENTER_CRITICAL(&tick_capture_mux);
  if (buf->count >= min_bits &&
      (uint32_t)(micros() - buf->last_bit_us) >= gap_us) {
    // Copy only the bytes actually in use; the rest is stale and never read.
    size_t used = (size_t)((buf->count + 7) / 8);
    memcpy(out->bits, buf->bits, used);
    out->count = buf->count;
    out->overflowed = buf->overflowed;
    out->last_bit_us = buf->last_bit_us;

    buf->count = 0;
    buf->overflowed = false;
    taken = true;
  }
  portEXIT_CRITICAL(&tick_capture_mux);

  return taken;
}

static inline uint8_t capture_bit(const tick_capture_buffer *buf, int index) {
  if (index < 0 || index >= (int)buf->count) return 0;
  return (buf->bits[index >> 3] >> (7 - (index & 7))) & 1;
}

size_t tick_capture_to_hex(const tick_capture_buffer *buf, char *out,
                           size_t out_len) {
  if (out_len == 0) return 0;

  size_t nibbles = (size_t)((buf->count + 3) / 4);
  if (nibbles + 1 > out_len) nibbles = out_len - 1;

  // The bit string is one big-endian integer rendered with ceil(count/4)
  // digits, so when the count is not a multiple of four the first nibble is
  // short and gets zero-padded on the left.
  int pad = (4 - (buf->count % 4)) % 4;

  for (size_t j = 0; j < nibbles; j++) {
    uint8_t value = 0;
    for (int k = 0; k < 4; k++) {
      int bit_index = (int)(j * 4 + k) - pad;
      value = (uint8_t)((value << 1) | capture_bit(buf, bit_index));
    }
    // Lowercase, matching what the old String-based path emitted. Every
    // consumer is case insensitive, but the log format is on disk and in the
    // web UI, so it is not worth changing on a device we cannot test against.
    out[j] = "0123456789abcdef"[value & 0x0F];
  }

  out[nibbles] = '\0';
  return nibbles;
}

size_t tick_capture_to_binary(const tick_capture_buffer *buf, char *out,
                              size_t out_len) {
  if (out_len == 0) return 0;

  size_t n = buf->count;
  if (n + 1 > out_len) n = out_len - 1;

  for (size_t i = 0; i < n; i++) {
    out[i] = capture_bit(buf, (int)i) ? '1' : '0';
  }

  out[n] = '\0';
  return n;
}

// --- transmit queue ---------------------------------------------------------

static char tx_pending_hex[TICK_TX_MAX_CHARS + 1];
static unsigned long tx_pending_bits = 0;
static volatile bool tx_pending = false;

static bool is_hex_digit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

bool tick_tx_submit(const char *hex, unsigned long bits) {
  if (hex == NULL) return false;

  size_t len = strnlen(hex, TICK_TX_MAX_CHARS + 1);
  if (len == 0 || len > TICK_TX_MAX_CHARS) return false;
  if (bits == 0 || bits > TICK_MAX_BITS) return false;

  for (size_t i = 0; i < len; i++) {
    if (!is_hex_digit(hex[i])) return false;
  }

  bool accepted = false;
  portENTER_CRITICAL(&tick_capture_mux);
  if (!tx_pending) {
    for (size_t i = 0; i < len; i++) {
      char c = hex[i];
      tx_pending_hex[i] = (c >= 'a' && c <= 'f') ? (char)(c - 'a' + 'A') : c;
    }
    tx_pending_hex[len] = '\0';
    tx_pending_bits = bits;
    tx_pending = true;
    accepted = true;
  }
  portEXIT_CRITICAL(&tick_capture_mux);

  return accepted;
}

bool tick_tx_submit_pair(const char *value) {
  if (value == NULL) return false;

  const char *colon = strchr(value, ':');
  if (colon == NULL || colon == value) return false;

  size_t hex_len = (size_t)(colon - value);
  if (hex_len > TICK_TX_MAX_CHARS) return false;

  char hex[TICK_TX_MAX_CHARS + 1];
  memcpy(hex, value, hex_len);
  hex[hex_len] = '\0';

  char *end = NULL;
  unsigned long bits = strtoul(colon + 1, &end, 10);
  if (end == colon + 1) return false;

  return tick_tx_submit(hex, bits);
}

void tick_tx_service(void) {
  if (!tx_pending) return;

  char hex[TICK_TX_MAX_CHARS + 1];
  unsigned long bits;

  portENTER_CRITICAL(&tick_capture_mux);
  memcpy(hex, tx_pending_hex, sizeof(hex));
  bits = tx_pending_bits;
  tx_pending = false;
  portEXIT_CRITICAL(&tick_capture_mux);

  if (tick_current->tx) {
    tick_current->tx(hex, strlen(hex), bits);
    append_log("tx", String(hex) + ":" + String(bits));
  } else {
    append_log("tx", String("refused, mode ") + tick_proto_name() +
                         " cannot transmit");
  }
}
