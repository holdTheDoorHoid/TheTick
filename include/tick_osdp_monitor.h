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

#ifndef TICK_OSDP_MONITOR_H
#define TICK_OSDP_MONITOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tick_osdp_dissect.h"

// Passive detection of the OSDP weaknesses Bishop Fox published as "Badge of
// Shame" (Black Hat / DEF CON 2023) and implemented in their Mellon tool.
//
// The Tick already sits where an attacker would sit - on the RS-485 pair
// between a reader and a controller - so the same position that makes the
// attacks possible makes them observable. This module watches the
// conversation and reports the conditions each attack depends on. It is
// passive: it parses, it never transmits.
//
// Mapping from the published attacks to what is detectable from the wire:
//
//   #1 Passive eavesdropping   A session that never establishes a secure
//                              channel, and card data visible in cleartext.
//                              Directly observable.
//   #2 Downgrade               A reader's capability reply claiming no
//                              encryption support. Observable, and a change
//                              in that claim between observations is a much
//                              stronger signal than the claim alone.
//   #3 Install mode            osdp_KEYSET accepted outside of a genuine
//                              commissioning window, especially repeatedly.
//                              Observable.
//   #4 Weak keys               Requires verifying a captured handshake
//                              against candidate keys, which needs AES. The
//                              candidate generator is here; the verification
//                              is not yet wired up.
//   #5 Keyset capture          osdp_KEYSET carries the secure channel base
//                              key over the wire. Any occurrence is worth an
//                              alert, because anyone listening now holds the
//                              key.

enum osdp_threat {
  OSDP_THREAT_NONE = 0,
  // The bus carries no secure channel at all: everything is readable.
  OSDP_THREAT_CLEARTEXT_SESSION,
  // A credential crossed the wire in the clear.
  OSDP_THREAT_CLEARTEXT_CARD_READ,
  // A reader advertised no encryption support, which is what a downgrade
  // attack forges.
  OSDP_THREAT_NO_CRYPTO_ADVERTISED,
  // A reader's advertised encryption support changed between observations.
  // Readers do not change their capabilities; something is rewriting them.
  OSDP_THREAT_CAPABILITY_CHANGED,
  // The secure channel base key was transmitted over the wire.
  OSDP_THREAT_KEYSET_ON_WIRE,
  // Repeated key installs, the signature of a controller left in install mode.
  OSDP_THREAT_INSTALL_MODE,
  // Many secure channel handshakes without one succeeding.
  OSDP_THREAT_SC_RETRY_STORM,
  // A sequence number that does not follow, which is what injected traffic
  // looks like from the side.
  OSDP_THREAT_SEQUENCE_ANOMALY,
  // A secure session dropped back to cleartext without a reset.
  OSDP_THREAT_SECURITY_REGRESSION,
  // The handshake declared SCBK-D, the default key printed in the
  // specification. It is public, so the channel protects nothing.
  OSDP_THREAT_DEFAULT_KEY,
  // The base key was recovered from the handshake by trying the patterns that
  // turn up as hardcoded keys in sample code.
  OSDP_THREAT_WEAK_KEY,
  // SCS_15/16: a security block that authenticates but does not encrypt.
  // Bishop Fox describe these as null ciphers. Credentials stay readable.
  OSDP_THREAT_NULL_CIPHER,
  OSDP_THREAT_COUNT
};

// How many peripheral addresses to track. An OSDP bus can hold 126, but a
// reader install behind one controller is one or two, and this has to live in
// ESP32 RAM alongside the radios.
#define OSDP_MONITOR_MAX_PEERS 4

// Consecutive handshakes without success before a retry storm is called.
#define OSDP_MONITOR_SC_RETRY_LIMIT 5
// Key installs before the controller is assumed to be stuck in install mode.
#define OSDP_MONITOR_KEYSET_LIMIT 2
// Cleartext frames from one peer, with no handshake ever seen, before the bus
// is called unencrypted. A healthy bus is briefly in the clear at startup -
// polls and capability discovery precede the handshake - so this has to be
// past that window or every healthy session reports itself as broken.
#define OSDP_MONITOR_CLEARTEXT_LIMIT 20

struct osdp_peer_state {
  bool in_use;
  uint8_t address;

  bool saw_handshake;      // any of SCS_11..14
  bool saw_secure_data;    // SCS_17/18, so the channel actually came up
  bool saw_cleartext_data; // a command or reply with no security block

  bool cap_known;
  bool cap_supports_crypto;  // from PDCAP function code 9

  uint16_t cleartext_frames;
  uint16_t keyset_count;
  uint16_t handshake_count;
  uint16_t cleartext_card_reads;

  bool seq_known;
  uint8_t last_seq;

  // Handshake capture, so that a challenge seen in one frame can be matched
  // with the response in the next.
  bool have_challenge;
  uint8_t cp_random[8];

  // Set when the base key was recovered. Held so the web interface can show
  // it: on this device that is the finding, not a secret to protect.
  bool key_recovered;
  uint8_t recovered_key[16];
};

// Reported once per detection, not once per frame: the monitor deduplicates
// so that a bus polling ten times a second does not fill the log with the
// same finding.
struct osdp_threat_report {
  osdp_threat threat;
  uint8_t address;
  uint8_t frame_id;   // command or reply that triggered it
  uint32_t count;     // how many times this has now been seen
};

typedef void (*osdp_threat_handler)(const osdp_threat_report *report,
                                    void *context);

// Longest card payload OSDP carries, matching the specification's event
// limit. Defined here rather than taken from libosdp so this file stays free
// of that dependency.
#define OSDP_CRED_MAX_BYTES 64

// A credential lifted off the wire in the clear. This is the thing that gets
// replayed, and the thing a client most wants to see written down.
struct osdp_credential {
  uint8_t address;
  uint8_t reader_no;
  uint8_t format;
  uint16_t bits;
  uint8_t bytes;
  uint8_t data[OSDP_CRED_MAX_BYTES];
};

typedef void (*osdp_credential_handler)(const osdp_credential *credential,
                                        void *context);

struct osdp_monitor {
  osdp_peer_state peers[OSDP_MONITOR_MAX_PEERS];
  uint32_t threat_counts[OSDP_THREAT_COUNT];
  bool threat_reported[OSDP_THREAT_COUNT];
  uint32_t frames_seen;
  uint32_t frames_bad;
  osdp_threat_handler handler;
  void *handler_context;

  osdp_credential_handler credential_handler;
  void *credential_context;
  uint32_t credentials_seen;
};

void osdp_monitor_init(osdp_monitor *mon, osdp_threat_handler handler,
                       void *context);

// Feed one parsed frame. Safe to call with frames whose trailer did not
// verify; those are counted and otherwise ignored, because acting on a frame
// that failed its own integrity check is how a monitor is made to cry wolf.
void osdp_monitor_feed(osdp_monitor *mon, const osdp_frame *frame);

// Feed raw bus bytes. Returns how many were consumed; the caller keeps any
// remainder and prepends it next time.
size_t osdp_monitor_feed_bytes(osdp_monitor *mon, const uint8_t *buf,
                               size_t len);

// Clear the "already reported" flags so a fresh assessment can be made,
// without losing the counts.
// Called for every credential observed in the clear. Only cleartext reads are
// reported: an encrypted one cannot be recovered, and pretending otherwise
// would put a credential in a report that was never actually exposed.
void osdp_monitor_set_credential_handler(osdp_monitor *mon,
                                         osdp_credential_handler handler,
                                         void *context);

// Decode a REPLY_RAW payload. Layout is reader_no, format, bit count low,
// bit count high, then ceil(bits/8) bytes of card data.
bool osdp_decode_card_read(const osdp_frame *frame, osdp_credential *out);

void osdp_monitor_rearm(osdp_monitor *mon);

// Look up a tracked peripheral, or null. Used to pull the evidence - a
// recovered key, for instance - that belongs with a reported finding.
const osdp_peer_state *osdp_monitor_peer(const osdp_monitor *mon,
                                         uint8_t address);

// Severity to file a given threat under, so the report ranks itself.
int osdp_threat_severity(osdp_threat threat);

const char *osdp_threat_name(osdp_threat threat);
const char *osdp_threat_description(osdp_threat threat);

// --- weak key candidates ----------------------------------------------------
//
// Bishop Fox enumerate roughly 768 patterns that turn up as hardcoded keys in
// sample code: a single byte repeated, and ascending or descending runs from
// each possible starting byte. Generating them is pure arithmetic and is
// tested; checking a captured handshake against them needs AES and is not
// wired up yet.

#define OSDP_WEAK_KEY_COUNT 768
#define OSDP_KEY_LEN 16

// Write candidate `index` (0..OSDP_WEAK_KEY_COUNT-1) into `key`.
// Returns false if the index is out of range.
bool osdp_weak_key_candidate(uint32_t index, uint8_t key[OSDP_KEY_LEN]);

// SCBK-D, the default base key printed in the OSDP specification. Published,
// therefore worthless as protection, and singled out by Bishop Fox for
// existing at all.
extern const uint8_t OSDP_SCBK_DEFAULT[OSDP_KEY_LEN];

// Recompute the peripheral's cryptogram from a candidate base key and the two
// nonces, and report whether it matches what the peripheral actually sent.
//
// Derivation, per the specification and cross-checked against libosdp:
//   S-ENC        = AES-128-ECB(SCBK, 01 82 RND.A[0..5] 00 00 00 00 00 00 00 00)
//   cryptogram   = AES-128-ECB(S-ENC, RND.A[8] || RND.B[8])
// All three inputs are visible on the wire, which is what makes a weak base
// key recoverable by anyone listening.
bool osdp_sc_key_matches(const uint8_t scbk[OSDP_KEY_LEN],
                         const uint8_t cp_random[8], const uint8_t pd_random[8],
                         const uint8_t pd_cryptogram[16]);

// Try every weak candidate against an observed handshake. Returns the index
// of the match and fills `out_key`, or -1 if none matched.
int osdp_sc_find_weak_key(const uint8_t cp_random[8],
                          const uint8_t pd_random[8],
                          const uint8_t pd_cryptogram[16],
                          uint8_t out_key[OSDP_KEY_LEN]);

#ifdef USE_OSDP_MONITOR
#include "tick_protocol.h"
extern const tick_protocol tick_protocol_osdp_monitor;
// Current monitor state, for the web interface.
const osdp_monitor *osdp_monitor_state(void);
#endif

#endif
