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

#ifndef TICK_OSDP_DISSECT_H
#define TICK_OSDP_DISSECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Passive OSDP frame dissector.
//
// libosdp is a conformant protocol stack: it can be a control panel or a
// peripheral device, and in either role it participates in the conversation.
// What it cannot do is watch someone else's conversation without joining it,
// which is exactly what a device sitting on the wire between a reader and a
// controller needs to do.
//
// This parses OSDP frames straight off the bus and reports what it sees. It
// never transmits, never holds keys, and never needs to be addressed. It is
// deliberately free of Arduino and libosdp dependencies so the same code runs
// on the device and under test on a development machine.
//
// Frame layout, per SIA OSDP v2.2.2 and confirmed against libosdp's phy
// layer:
//
//   [0xFF]      optional MARK byte
//   0x53        SOM
//   address     bit 7 set means this is a reply from the PD
//   len_lsb     total frame length, SOM through trailer, excluding MARK
//   len_msb
//   control     bits 0-1 sequence, bit 2 CRC (else checksum), bit 3 SCB
//   [scb]       security block, present when control bit 3 is set:
//               scb[0] = length, scb[1] = type (SCS_11..SCS_18)
//   id          command code (CP->PD) or reply code (PD->CP)
//   payload     command or reply data
//   trailer     CRC-16 (2 bytes) or one byte checksum

#define OSDP_PKT_MARK 0xFF
#define OSDP_PKT_SOM 0x53

#define OSDP_HEADER_LEN 5
#define OSDP_MAX_FRAME 1024

// Security block types. Below SCS_15 these are the handshake itself; SCS_15
// and SCS_16 carry a MAC with cleartext data; SCS_17 and SCS_18 are the only
// ones where the payload is actually encrypted.
#define OSDP_SCS_11 0x11  // CP -> PD, CMD_CHLNG
#define OSDP_SCS_12 0x12  // PD -> CP, REPLY_CCRYPT
#define OSDP_SCS_13 0x13  // CP -> PD, CMD_SCRYPT
#define OSDP_SCS_14 0x14  // PD -> CP, REPLY_RMAC_I
#define OSDP_SCS_15 0x15  // CP -> PD, MAC, no encryption
#define OSDP_SCS_16 0x16  // PD -> CP, MAC, no encryption
#define OSDP_SCS_17 0x17  // CP -> PD, MAC and encryption
#define OSDP_SCS_18 0x18  // PD -> CP, MAC and encryption

// Commands (CP -> PD), from SIA OSDP v2.2.2.
#define OSDP_CMD_POLL 0x60
#define OSDP_CMD_ID 0x61
#define OSDP_CMD_CAP 0x62
#define OSDP_CMD_LSTAT 0x64
#define OSDP_CMD_ISTAT 0x65
#define OSDP_CMD_OSTAT 0x66
#define OSDP_CMD_RSTAT 0x67
#define OSDP_CMD_OUT 0x68
#define OSDP_CMD_LED 0x69
#define OSDP_CMD_BUZ 0x6A
#define OSDP_CMD_TEXT 0x6B
#define OSDP_CMD_RMODE 0x6C
#define OSDP_CMD_TDSET 0x6D
#define OSDP_CMD_COMSET 0x6E
#define OSDP_CMD_BIOREAD 0x73
#define OSDP_CMD_BIOMATCH 0x74
#define OSDP_CMD_KEYSET 0x75
#define OSDP_CMD_CHLNG 0x76
#define OSDP_CMD_SCRYPT 0x77
#define OSDP_CMD_ACURXSIZE 0x7B
#define OSDP_CMD_FILETRANSFER 0x7C
#define OSDP_CMD_MFG 0x80
#define OSDP_CMD_XWR 0xA1
#define OSDP_CMD_ABORT 0xA2
#define OSDP_CMD_PIVDATA 0xA3
#define OSDP_CMD_GENAUTH 0xA4
#define OSDP_CMD_CRAUTH 0xA5
#define OSDP_CMD_KEEPACTIVE 0xA7

// Replies (PD -> CP).
#define OSDP_REPLY_ACK 0x40
#define OSDP_REPLY_NAK 0x41
#define OSDP_REPLY_PDID 0x45
#define OSDP_REPLY_PDCAP 0x46
#define OSDP_REPLY_LSTATR 0x48
#define OSDP_REPLY_ISTATR 0x49
#define OSDP_REPLY_OSTATR 0x4A
#define OSDP_REPLY_RSTATR 0x4B
#define OSDP_REPLY_RAW 0x50
#define OSDP_REPLY_FMT 0x51
#define OSDP_REPLY_KEYPAD 0x53
#define OSDP_REPLY_COM 0x54
#define OSDP_REPLY_BIOREADR 0x57
#define OSDP_REPLY_BIOMATCHR 0x58
#define OSDP_REPLY_CCRYPT 0x76
#define OSDP_REPLY_RMAC_I 0x78
#define OSDP_REPLY_BUSY 0x79
#define OSDP_REPLY_FTSTAT 0x7A
#define OSDP_REPLY_PIVDATAR 0x80
#define OSDP_REPLY_GENAUTHR 0x81
#define OSDP_REPLY_CRAUTHR 0x82
#define OSDP_REPLY_MFGSTATR 0x83
#define OSDP_REPLY_MFGERRR 0x84
#define OSDP_REPLY_MFGREP 0x90
#define OSDP_REPLY_XRD 0xB1

// Capability function codes, needed to read a PDCAP reply.
#define OSDP_PD_CAP_CONTACT_STATUS 1
#define OSDP_PD_CAP_OUTPUT_CONTROL 2
#define OSDP_PD_CAP_CARD_DATA_FORMAT 3
#define OSDP_PD_CAP_READER_LED_CONTROL 4
#define OSDP_PD_CAP_READER_AUDIBLE_OUTPUT 5
#define OSDP_PD_CAP_READER_TEXT_OUTPUT 6
#define OSDP_PD_CAP_TIME_KEEPING 7
#define OSDP_PD_CAP_CHECK_CHARACTER_SUPPORT 8
#define OSDP_PD_CAP_COMMUNICATION_SECURITY 9
#define OSDP_PD_CAP_RECEIVE_BUFFERSIZE 10
#define OSDP_PD_CAP_LARGEST_COMBINED_MESSAGE_SIZE 11
#define OSDP_PD_CAP_SMART_CARD_SUPPORT 12
#define OSDP_PD_CAP_READERS 13
#define OSDP_PD_CAP_BIOMETRICS 14

struct osdp_frame {
  bool has_mark;
  uint8_t address;  // 7 bit address, reply flag stripped
  bool is_reply;    // true when the frame came from the PD
  uint16_t length;  // as declared in the header
  uint8_t sequence;
  bool uses_crc;  // false means the weaker one byte checksum

  bool has_scb;
  uint8_t scb_len;
  uint8_t scb_type;
  const uint8_t *scb_data;
  uint8_t scb_data_len;

  uint8_t id;  // command or reply code
  const uint8_t *payload;
  uint16_t payload_len;

  bool trailer_valid;  // CRC or checksum matched
  bool payload_encrypted;  // SCS_17/18: payload is ciphertext, not readable
};

enum osdp_dissect_result {
  OSDP_DISSECT_OK = 0,
  OSDP_DISSECT_NEED_MORE,    // truncated, wait for more bytes
  OSDP_DISSECT_NO_SOM,       // no start of message in this buffer
  OSDP_DISSECT_BAD_LENGTH,   // declared length is impossible
  OSDP_DISSECT_BAD_SCB,      // security block runs past the frame
  OSDP_DISSECT_BAD_TRAILER,  // CRC or checksum mismatch
};

// The OSDP CRC-16, seeded 0x1D0F.
uint16_t osdp_crc16(const uint8_t *buf, size_t len);

// The one byte checksum used when the CRC control bit is clear.
uint8_t osdp_checksum(const uint8_t *buf, size_t len);

// Parse one frame starting at buf[0], which must be MARK or SOM.
// `consumed` receives the number of bytes the frame occupies. `out->payload`
// and `out->scb_data` point into `buf`, so they are valid only as long as it
// is.
osdp_dissect_result osdp_dissect(const uint8_t *buf, size_t len,
                                 osdp_frame *out, size_t *consumed);

// Find and parse the next frame anywhere in `buf`, skipping leading noise.
// `offset` receives where the frame started, `consumed` its length from
// there. A bus is a shared medium and a listener joins mid-conversation, so
// resynchronising on SOM is the normal case, not an error path.
osdp_dissect_result osdp_dissect_stream(const uint8_t *buf, size_t len,
                                        osdp_frame *out, size_t *offset,
                                        size_t *consumed);

// Human readable names, for the log and the web UI.
const char *osdp_command_name(uint8_t id);
const char *osdp_reply_name(uint8_t id);
const char *osdp_frame_name(const osdp_frame *frame);

#endif
