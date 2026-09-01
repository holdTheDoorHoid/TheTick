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

#include "tick_osdp_dissect.h"

// Deliberately no Arduino or libosdp includes: this file is compiled both
// into the firmware and directly into the host test binary.

#define PKT_CONTROL_SQN 0x03
#define PKT_CONTROL_CRC 0x04
#define PKT_CONTROL_SCB 0x08

uint16_t osdp_crc16(const uint8_t *buf, size_t len) {
  // CRC-16/ITU-T seeded with 0x1D0F, matching libosdp and the OSDP
  // specification.
  uint16_t seed = 0x1D0F;
  for (; len > 0; len--) {
    seed = (uint16_t)((seed >> 8U) | (seed << 8U));
    seed ^= *buf++;
    seed ^= (uint16_t)((seed & 0xffU) >> 4U);
    seed ^= (uint16_t)(seed << 12U);
    seed ^= (uint16_t)((seed & 0xffU) << 5U);
  }
  return seed;
}

uint8_t osdp_checksum(const uint8_t *buf, size_t len) {
  uint8_t checksum = 0;
  int whole = 0;
  for (size_t i = 0; i < len; i++) {
    whole += buf[i];
    checksum = (uint8_t)(~(0xff & whole) + 1);
  }
  return checksum;
}

osdp_dissect_result osdp_dissect(const uint8_t *buf, size_t len,
                                 osdp_frame *out, size_t *consumed) {
  if (out == NULL || buf == NULL) return OSDP_DISSECT_NO_SOM;

  osdp_frame f;
  f.has_mark = false;
  f.payload_encrypted = false;
  f.scb_data = NULL;
  f.scb_data_len = 0;
  f.scb_len = 0;
  f.scb_type = 0;
  f.has_scb = false;
  f.payload = NULL;
  f.payload_len = 0;

  size_t offset = 0;
  if (len > 0 && buf[0] == OSDP_PKT_MARK) {
    f.has_mark = true;
    offset = 1;
  }

  if (len < offset + 1) return OSDP_DISSECT_NEED_MORE;
  if (buf[offset] != OSDP_PKT_SOM) return OSDP_DISSECT_NO_SOM;

  if (len < offset + OSDP_HEADER_LEN) return OSDP_DISSECT_NEED_MORE;

  const uint8_t *pkt = buf + offset;

  uint8_t address = pkt[1];
  f.is_reply = (address & 0x80) != 0;
  f.address = (uint8_t)(address & 0x7F);
  f.length = (uint16_t)(pkt[2] | (pkt[3] << 8));

  uint8_t control = pkt[4];
  f.sequence = (uint8_t)(control & PKT_CONTROL_SQN);
  f.uses_crc = (control & PKT_CONTROL_CRC) != 0;
  f.has_scb = (control & PKT_CONTROL_SCB) != 0;

  size_t trailer_len = f.uses_crc ? 2u : 1u;

  // A frame must at least carry a header, an id byte and a trailer. Checking
  // this before any subtraction keeps the arithmetic below from wrapping on a
  // malformed or hostile length field.
  if (f.length < OSDP_HEADER_LEN + 1 + trailer_len) {
    return OSDP_DISSECT_BAD_LENGTH;
  }
  if (f.length > OSDP_MAX_FRAME) return OSDP_DISSECT_BAD_LENGTH;

  if (len < offset + f.length) return OSDP_DISSECT_NEED_MORE;

  size_t body = OSDP_HEADER_LEN;  // index into pkt of the SCB or id byte

  if (f.has_scb) {
    if (f.length < OSDP_HEADER_LEN + 2 + 1 + trailer_len) {
      return OSDP_DISSECT_BAD_SCB;
    }
    f.scb_len = pkt[OSDP_HEADER_LEN];
    // The security block counts its own length byte and type byte.
    if (f.scb_len < 2) return OSDP_DISSECT_BAD_SCB;
    if ((size_t)OSDP_HEADER_LEN + f.scb_len + 1 + trailer_len > f.length) {
      return OSDP_DISSECT_BAD_SCB;
    }
    f.scb_type = pkt[OSDP_HEADER_LEN + 1];
    f.scb_data = pkt + OSDP_HEADER_LEN + 2;
    f.scb_data_len = (uint8_t)(f.scb_len - 2);
    body = OSDP_HEADER_LEN + f.scb_len;

    // Only these two carry an encrypted payload. Everything else with a
    // security block is authenticated but readable, which is the distinction
    // that makes passive monitoring possible at all.
    f.payload_encrypted = (f.scb_type == OSDP_SCS_17 || f.scb_type == OSDP_SCS_18);
  }

  f.id = pkt[body];

  size_t payload_start = body + 1;
  size_t payload_end = f.length - trailer_len;
  f.payload = pkt + payload_start;
  f.payload_len = (uint16_t)(payload_end - payload_start);

  // Verify the trailer over everything before it.
  if (f.uses_crc) {
    uint16_t want = (uint16_t)(pkt[f.length - 2] | (pkt[f.length - 1] << 8));
    f.trailer_valid = (osdp_crc16(pkt, f.length - 2) == want);
  } else {
    f.trailer_valid = (osdp_checksum(pkt, f.length - 1) == pkt[f.length - 1]);
  }

  *out = f;
  if (consumed) *consumed = offset + f.length;
  return f.trailer_valid ? OSDP_DISSECT_OK : OSDP_DISSECT_BAD_TRAILER;
}

osdp_dissect_result osdp_dissect_stream(const uint8_t *buf, size_t len,
                                        osdp_frame *out, size_t *offset,
                                        size_t *consumed) {
  if (buf == NULL || out == NULL) return OSDP_DISSECT_NO_SOM;

  osdp_dissect_result last_partial = OSDP_DISSECT_NO_SOM;

  for (size_t i = 0; i < len; i++) {
    if (buf[i] != OSDP_PKT_SOM && buf[i] != OSDP_PKT_MARK) continue;
    // A MARK is only a frame start when a SOM follows it.
    if (buf[i] == OSDP_PKT_MARK && (i + 1 >= len || buf[i + 1] != OSDP_PKT_SOM)) {
      continue;
    }

    size_t used = 0;
    osdp_dissect_result r = osdp_dissect(buf + i, len - i, out, &used);
    if (r == OSDP_DISSECT_OK || r == OSDP_DISSECT_BAD_TRAILER) {
      if (offset) *offset = i;
      if (consumed) *consumed = used;
      return r;
    }
    if (r == OSDP_DISSECT_NEED_MORE) {
      // Truncated at the end of the buffer: tell the caller to keep the tail
      // and come back with more, rather than discarding a real frame.
      if (offset) *offset = i;
      if (consumed) *consumed = 0;
      return OSDP_DISSECT_NEED_MORE;
    }
    // A bad length or security block here was noise that happened to contain
    // 0x53. Keep scanning.
    last_partial = r;
  }

  if (offset) *offset = len;
  if (consumed) *consumed = 0;
  return last_partial == OSDP_DISSECT_NO_SOM ? OSDP_DISSECT_NO_SOM
                                             : last_partial;
}

const char *osdp_command_name(uint8_t id) {
  switch (id) {
    case OSDP_CMD_POLL: return "POLL";
    case OSDP_CMD_ID: return "ID";
    case OSDP_CMD_CAP: return "CAP";
    case OSDP_CMD_LSTAT: return "LSTAT";
    case OSDP_CMD_ISTAT: return "ISTAT";
    case OSDP_CMD_OSTAT: return "OSTAT";
    case OSDP_CMD_RSTAT: return "RSTAT";
    case OSDP_CMD_OUT: return "OUT";
    case OSDP_CMD_LED: return "LED";
    case OSDP_CMD_BUZ: return "BUZ";
    case OSDP_CMD_TEXT: return "TEXT";
    case OSDP_CMD_RMODE: return "RMODE";
    case OSDP_CMD_TDSET: return "TDSET";
    case OSDP_CMD_COMSET: return "COMSET";
    case OSDP_CMD_BIOREAD: return "BIOREAD";
    case OSDP_CMD_BIOMATCH: return "BIOMATCH";
    case OSDP_CMD_KEYSET: return "KEYSET";
    case OSDP_CMD_CHLNG: return "CHLNG";
    case OSDP_CMD_SCRYPT: return "SCRYPT";
    case OSDP_CMD_ACURXSIZE: return "ACURXSIZE";
    case OSDP_CMD_FILETRANSFER: return "FILETRANSFER";
    case OSDP_CMD_MFG: return "MFG";
    case OSDP_CMD_XWR: return "XWR";
    case OSDP_CMD_ABORT: return "ABORT";
    case OSDP_CMD_PIVDATA: return "PIVDATA";
    case OSDP_CMD_GENAUTH: return "GENAUTH";
    case OSDP_CMD_CRAUTH: return "CRAUTH";
    case OSDP_CMD_KEEPACTIVE: return "KEEPACTIVE";
    default: return "UNKNOWN";
  }
}

const char *osdp_reply_name(uint8_t id) {
  switch (id) {
    case OSDP_REPLY_ACK: return "ACK";
    case OSDP_REPLY_NAK: return "NAK";
    case OSDP_REPLY_PDID: return "PDID";
    case OSDP_REPLY_PDCAP: return "PDCAP";
    case OSDP_REPLY_LSTATR: return "LSTATR";
    case OSDP_REPLY_ISTATR: return "ISTATR";
    case OSDP_REPLY_OSTATR: return "OSTATR";
    case OSDP_REPLY_RSTATR: return "RSTATR";
    case OSDP_REPLY_RAW: return "RAW";
    case OSDP_REPLY_FMT: return "FMT";
    case OSDP_REPLY_KEYPAD: return "KEYPAD";
    case OSDP_REPLY_COM: return "COM";
    case OSDP_REPLY_BIOREADR: return "BIOREADR";
    case OSDP_REPLY_BIOMATCHR: return "BIOMATCHR";
    case OSDP_REPLY_CCRYPT: return "CCRYPT";
    case OSDP_REPLY_RMAC_I: return "RMAC_I";
    case OSDP_REPLY_BUSY: return "BUSY";
    case OSDP_REPLY_FTSTAT: return "FTSTAT";
    case OSDP_REPLY_PIVDATAR: return "PIVDATAR";
    case OSDP_REPLY_GENAUTHR: return "GENAUTHR";
    case OSDP_REPLY_CRAUTHR: return "CRAUTHR";
    case OSDP_REPLY_MFGSTATR: return "MFGSTATR";
    case OSDP_REPLY_MFGERRR: return "MFGERRR";
    case OSDP_REPLY_MFGREP: return "MFGREP";
    case OSDP_REPLY_XRD: return "XRD";
    default: return "UNKNOWN";
  }
}

const char *osdp_frame_name(const osdp_frame *frame) {
  if (frame == NULL) return "UNKNOWN";
  return frame->is_reply ? osdp_reply_name(frame->id)
                         : osdp_command_name(frame->id);
}
