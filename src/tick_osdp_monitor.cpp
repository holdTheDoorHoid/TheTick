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

#include "tick_osdp_monitor.h"

#include <string.h>

#include "tick_aes128.h"

// No Arduino dependency here either: the whole detection path is exercised on
// the host, where a synthetic bus transcript can be replayed through it.

static osdp_peer_state *peer_for(osdp_monitor *mon, uint8_t address) {
  for (int i = 0; i < OSDP_MONITOR_MAX_PEERS; i++) {
    if (mon->peers[i].in_use && mon->peers[i].address == address) {
      return &mon->peers[i];
    }
  }
  for (int i = 0; i < OSDP_MONITOR_MAX_PEERS; i++) {
    if (!mon->peers[i].in_use) {
      memset(&mon->peers[i], 0, sizeof(mon->peers[i]));
      mon->peers[i].in_use = true;
      mon->peers[i].address = address;
      return &mon->peers[i];
    }
  }
  // More addresses than slots. Returning null means those frames are counted
  // but not attributed, which is better than evicting a peer whose history is
  // the thing that makes a downgrade detectable.
  return NULL;
}

static void raise(osdp_monitor *mon, osdp_threat threat, uint8_t address,
                  uint8_t frame_id) {
  if (threat <= OSDP_THREAT_NONE || threat >= OSDP_THREAT_COUNT) return;

  mon->threat_counts[threat]++;

  // Report the first occurrence only, until rearmed. A polled bus repeats the
  // same conditions several times a second.
  if (mon->threat_reported[threat]) return;
  mon->threat_reported[threat] = true;

  if (mon->handler) {
    osdp_threat_report report;
    report.threat = threat;
    report.address = address;
    report.frame_id = frame_id;
    report.count = mon->threat_counts[threat];
    mon->handler(&report, mon->handler_context);
  }
}

void osdp_monitor_init(osdp_monitor *mon, osdp_threat_handler handler,
                       void *context) {
  memset(mon, 0, sizeof(*mon));
  mon->handler = handler;
  mon->handler_context = context;
}

void osdp_monitor_rearm(osdp_monitor *mon) {
  memset(mon->threat_reported, 0, sizeof(mon->threat_reported));
}

// A PDCAP reply is a list of three byte entries: function code, compliance
// level, number of items. Function code 9 is communication security, where a
// compliance level of zero means the reader is telling the controller it
// cannot do AES - which is exactly what a downgrade attack forges.
static bool parse_crypto_capability(const osdp_frame *frame, bool *supports) {
  if (frame->payload == NULL) return false;
  for (uint16_t i = 0; i + 2 < frame->payload_len; i += 3) {
    if (frame->payload[i] == OSDP_PD_CAP_COMMUNICATION_SECURITY) {
      *supports = frame->payload[i + 1] != 0;
      return true;
    }
  }
  return false;
}

static bool frame_carries_credential(const osdp_frame *frame) {
  if (!frame->is_reply) return false;
  return frame->id == OSDP_REPLY_RAW || frame->id == OSDP_REPLY_FMT ||
         frame->id == OSDP_REPLY_KEYPAD;
}

void osdp_monitor_feed(osdp_monitor *mon, const osdp_frame *frame) {
  if (mon == NULL || frame == NULL) return;

  mon->frames_seen++;

  // A frame whose own integrity check failed says nothing reliable about the
  // bus. Count it and move on rather than raising findings from noise.
  if (!frame->trailer_valid) {
    mon->frames_bad++;
    return;
  }

  osdp_peer_state *peer = peer_for(mon, frame->address);
  if (peer == NULL) return;

  // --- secure channel state -------------------------------------------------

  if (frame->has_scb) {
    switch (frame->scb_type) {
      case OSDP_SCS_11:
        peer->saw_handshake = true;
        peer->handshake_count++;
        // The third byte of the security block says whether the default key
        // is in use. Zero means SCBK-D, which is printed in the
        // specification and therefore protects nothing.
        if (frame->scb_data_len >= 1 && frame->scb_data[0] == 0) {
          raise(mon, OSDP_THREAT_DEFAULT_KEY, frame->address, frame->id);
        }
        // Keep RND.A so it can be paired with the response.
        if (!frame->is_reply && frame->id == OSDP_CMD_CHLNG &&
            frame->payload_len >= 8) {
          memcpy(peer->cp_random, frame->payload, 8);
          peer->have_challenge = true;
        }
        if (!peer->saw_secure_data &&
            peer->handshake_count > OSDP_MONITOR_SC_RETRY_LIMIT) {
          raise(mon, OSDP_THREAT_SC_RETRY_STORM, frame->address, frame->id);
        }
        break;
      case OSDP_SCS_13:
        peer->saw_handshake = true;
        peer->handshake_count++;
        // Many attempts without the channel ever coming up is what key
        // guessing looks like from the outside.
        if (!peer->saw_secure_data &&
            peer->handshake_count > OSDP_MONITOR_SC_RETRY_LIMIT) {
          raise(mon, OSDP_THREAT_SC_RETRY_STORM, frame->address, frame->id);
        }
        break;
      case OSDP_SCS_12:
        peer->saw_handshake = true;
        if (frame->scb_data_len >= 1 && frame->scb_data[0] == 0) {
          raise(mon, OSDP_THREAT_DEFAULT_KEY, frame->address, frame->id);
        }
        // REPLY_CCRYPT carries cUID(8) || RND.B(8) || cryptogram(16). With
        // RND.A from the challenge, every input to the key derivation is now
        // in hand, so a base key drawn from the usual sample-code patterns
        // can be recovered by anyone who was listening.
        if (peer->have_challenge && frame->is_reply &&
            frame->id == OSDP_REPLY_CCRYPT && frame->payload_len >= 32) {
          const uint8_t *pd_random = frame->payload + 8;
          const uint8_t *cryptogram = frame->payload + 16;

          if (osdp_sc_key_matches(OSDP_SCBK_DEFAULT, peer->cp_random, pd_random,
                                  cryptogram)) {
            peer->key_recovered = true;
            memcpy(peer->recovered_key, OSDP_SCBK_DEFAULT, OSDP_KEY_LEN);
            raise(mon, OSDP_THREAT_DEFAULT_KEY, frame->address, frame->id);
          } else {
            uint8_t found[OSDP_KEY_LEN];
            if (osdp_sc_find_weak_key(peer->cp_random, pd_random, cryptogram,
                                      found) >= 0) {
              peer->key_recovered = true;
              memcpy(peer->recovered_key, found, OSDP_KEY_LEN);
              raise(mon, OSDP_THREAT_WEAK_KEY, frame->address, frame->id);
            }
          }
          peer->have_challenge = false;
        }
        break;
      case OSDP_SCS_14:
        peer->saw_handshake = true;
        break;
      case OSDP_SCS_17:
      case OSDP_SCS_18:
        // The channel is genuinely up and the payload is ciphertext.
        peer->saw_secure_data = true;
        peer->handshake_count = 0;
        break;
      case OSDP_SCS_15:
      case OSDP_SCS_16:
        // Authenticated but not encrypted. The specification allows this and
        // Bishop Fox call it a null cipher: the frame is protected against
        // tampering and readable by anyone.
        raise(mon, OSDP_THREAT_NULL_CIPHER, frame->address, frame->id);
        break;
      default:
        break;
    }
  } else {
    peer->saw_cleartext_data = true;
    if (peer->cleartext_frames < 0xFFFF) peer->cleartext_frames++;

    // Dropping out of a working secure channel back to no security block at
    // all, without a fresh handshake, is a regression worth shouting about:
    // it is what an attacker forcing a downgrade mid-session produces.
    if (peer->saw_secure_data) {
      raise(mon, OSDP_THREAT_SECURITY_REGRESSION, frame->address, frame->id);
    }
  }

  // --- credentials in the clear --------------------------------------------

  if (frame_carries_credential(frame) && !frame->payload_encrypted) {
    peer->cleartext_card_reads++;
    raise(mon, OSDP_THREAT_CLEARTEXT_CARD_READ, frame->address, frame->id);
  }

  // A bus that has been talking for a while with no secure channel in sight
  // is simply unencrypted, which is Bishop Fox's first finding. Counted per
  // peer and past the startup window, so a healthy session that polls a few
  // times before its handshake is not reported as broken.
  if (!peer->saw_handshake && !peer->saw_secure_data &&
      peer->cleartext_frames > OSDP_MONITOR_CLEARTEXT_LIMIT) {
    raise(mon, OSDP_THREAT_CLEARTEXT_SESSION, frame->address, frame->id);
  }

  // --- capability handling --------------------------------------------------

  if (frame->is_reply && frame->id == OSDP_REPLY_PDCAP &&
      !frame->payload_encrypted) {
    bool supports = false;
    if (parse_crypto_capability(frame, &supports)) {
      if (peer->cap_known && peer->cap_supports_crypto != supports) {
        // Readers do not change what they are. Something between the reader
        // and the controller is rewriting this message.
        raise(mon, OSDP_THREAT_CAPABILITY_CHANGED, frame->address, frame->id);
      }
      peer->cap_known = true;
      peer->cap_supports_crypto = supports;

      if (!supports) {
        raise(mon, OSDP_THREAT_NO_CRYPTO_ADVERTISED, frame->address, frame->id);
      }
    }
  }

  // --- key material on the wire --------------------------------------------

  if (!frame->is_reply && frame->id == OSDP_CMD_KEYSET) {
    peer->keyset_count++;

    // Whether or not it is encrypted, a key install is the moment Bishop
    // Fox's fifth attack waits for. Unencrypted, the key is simply readable.
    raise(mon, OSDP_THREAT_KEYSET_ON_WIRE, frame->address, frame->id);

    if (peer->keyset_count > OSDP_MONITOR_KEYSET_LIMIT) {
      // Commissioning happens once. Repeated installs mean the controller
      // never left install mode.
      raise(mon, OSDP_THREAT_INSTALL_MODE, frame->address, frame->id);
    }
  }

  // --- sequence tracking ----------------------------------------------------
  //
  // OSDP sequence numbers cycle 1,2,3,1,2,3... with 0 reserved for a bus
  // reset. Commands and replies carry the same number, so only one side is
  // tracked to avoid double counting.

  if (!frame->is_reply) {
    if (peer->seq_known && frame->sequence != 0) {
      uint8_t expected = (uint8_t)(peer->last_seq >= 3 ? 1 : peer->last_seq + 1);

      // Three tolerated cases, or this fires constantly on healthy hardware:
      //
      //   - the expected next number;
      //   - a repeat of the last, which is a retransmission after a missed
      //     reply, and normal on a long cable;
      //   - a restart at 1, which OSDP does legitimately whenever a secure
      //     channel is established and whenever a peripheral reboots.
      //
      // Tolerating the restart does cost coverage: an injected frame that
      // happens to carry sequence 1 is not flagged here. That is the right
      // trade. A detector that reports every secure channel setup as an
      // attack is one an operator switches off, and the attacks this module
      // exists to catch are detected by the checks above rather than by
      // sequence tracking.
      bool tolerated = frame->sequence == expected ||
                       frame->sequence == peer->last_seq ||
                       frame->sequence == 1;
      if (!tolerated) {
        raise(mon, OSDP_THREAT_SEQUENCE_ANOMALY, frame->address, frame->id);
      }
    }
    peer->last_seq = frame->sequence;
    peer->seq_known = true;
  }
}

size_t osdp_monitor_feed_bytes(osdp_monitor *mon, const uint8_t *buf,
                               size_t len) {
  if (mon == NULL || buf == NULL) return 0;

  size_t pos = 0;
  while (pos < len) {
    osdp_frame frame;
    size_t offset = 0, consumed = 0;
    osdp_dissect_result r =
        osdp_dissect_stream(buf + pos, len - pos, &frame, &offset, &consumed);

    if (r == OSDP_DISSECT_OK || r == OSDP_DISSECT_BAD_TRAILER) {
      osdp_monitor_feed(mon, &frame);
      pos += offset + consumed;
      continue;
    }

    if (r == OSDP_DISSECT_NEED_MORE) {
      // Keep the partial frame for next time.
      return pos + offset;
    }

    // Nothing usable in what remains.
    return len;
  }
  return pos;
}

const char *osdp_threat_name(osdp_threat threat) {
  switch (threat) {
    case OSDP_THREAT_CLEARTEXT_SESSION: return "cleartext_session";
    case OSDP_THREAT_CLEARTEXT_CARD_READ: return "cleartext_card_read";
    case OSDP_THREAT_NO_CRYPTO_ADVERTISED: return "no_crypto_advertised";
    case OSDP_THREAT_CAPABILITY_CHANGED: return "capability_changed";
    case OSDP_THREAT_KEYSET_ON_WIRE: return "keyset_on_wire";
    case OSDP_THREAT_INSTALL_MODE: return "install_mode";
    case OSDP_THREAT_SC_RETRY_STORM: return "sc_retry_storm";
    case OSDP_THREAT_SEQUENCE_ANOMALY: return "sequence_anomaly";
    case OSDP_THREAT_SECURITY_REGRESSION: return "security_regression";
    case OSDP_THREAT_DEFAULT_KEY: return "default_key";
    case OSDP_THREAT_WEAK_KEY: return "weak_key";
    case OSDP_THREAT_NULL_CIPHER: return "null_cipher";
    default: return "none";
  }
}

const char *osdp_threat_description(osdp_threat threat) {
  switch (threat) {
    case OSDP_THREAT_CLEARTEXT_SESSION:
      return "This bus is running without a secure channel. Anyone on the "
             "wire can read every credential.";
    case OSDP_THREAT_CLEARTEXT_CARD_READ:
      return "A credential crossed the wire unencrypted and could be copied.";
    case OSDP_THREAT_NO_CRYPTO_ADVERTISED:
      return "The reader told the controller it cannot do encryption. Either "
             "it genuinely cannot, or something rewrote that message.";
    case OSDP_THREAT_CAPABILITY_CHANGED:
      return "The reader's advertised encryption support changed. Readers do "
             "not change; a device in the wire is rewriting capabilities.";
    case OSDP_THREAT_KEYSET_ON_WIRE:
      return "A secure channel key was installed over the wire. Anyone "
             "listening at that moment now holds it.";
    case OSDP_THREAT_INSTALL_MODE:
      return "Keys have been installed repeatedly, so the controller is "
             "likely still in install mode and will hand a key to anyone who "
             "asks.";
    case OSDP_THREAT_SC_RETRY_STORM:
      return "Repeated secure channel handshakes that never succeed, which is "
             "what key guessing looks like.";
    case OSDP_THREAT_SEQUENCE_ANOMALY:
      return "A message arrived out of sequence, which is what injected "
             "traffic looks like from the side.";
    case OSDP_THREAT_SECURITY_REGRESSION:
      return "A session that was encrypted fell back to cleartext without a "
             "reset.";
    case OSDP_THREAT_DEFAULT_KEY:
      return "The secure channel is using SCBK-D, the default key printed in "
             "the OSDP specification. It is public, so the encryption "
             "protects nothing.";
    case OSDP_THREAT_WEAK_KEY:
      return "The base key was recovered from the handshake by trying the "
             "patterns that appear as hardcoded keys in sample code. Anyone "
             "listening can decrypt this bus.";
    case OSDP_THREAT_NULL_CIPHER:
      return "The secure channel is running in a mode that authenticates but "
             "does not encrypt, so credentials remain readable on the wire.";
    default:
      return "";
  }
}

// --- secure channel key oracle ----------------------------------------------

const uint8_t OSDP_SCBK_DEFAULT[OSDP_KEY_LEN] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F};

bool osdp_sc_key_matches(const uint8_t scbk[OSDP_KEY_LEN],
                         const uint8_t cp_random[8], const uint8_t pd_random[8],
                         const uint8_t pd_cryptogram[16]) {
  // S-ENC = AES-ECB(SCBK, 01 82 RND.A[0..5] then zeroes)
  uint8_t s_enc[16];
  memset(s_enc, 0, sizeof(s_enc));
  s_enc[0] = 0x01;
  s_enc[1] = 0x82;
  memcpy(s_enc + 2, cp_random, 6);
  aes128_encrypt(scbk, s_enc, s_enc);

  // cryptogram = AES-ECB(S-ENC, RND.A || RND.B)
  uint8_t expected[16];
  memcpy(expected, cp_random, 8);
  memcpy(expected + 8, pd_random, 8);
  aes128_encrypt(s_enc, expected, expected);

  return memcmp(expected, pd_cryptogram, 16) == 0;
}

int osdp_sc_find_weak_key(const uint8_t cp_random[8],
                          const uint8_t pd_random[8],
                          const uint8_t pd_cryptogram[16],
                          uint8_t out_key[OSDP_KEY_LEN]) {
  uint8_t key[OSDP_KEY_LEN];
  for (uint32_t i = 0; i < OSDP_WEAK_KEY_COUNT; i++) {
    if (!osdp_weak_key_candidate(i, key)) break;
    if (osdp_sc_key_matches(key, cp_random, pd_random, pd_cryptogram)) {
      if (out_key) memcpy(out_key, key, OSDP_KEY_LEN);
      return (int)i;
    }
  }
  return -1;
}

// --- weak key candidates ----------------------------------------------------

bool osdp_weak_key_candidate(uint32_t index, uint8_t key[OSDP_KEY_LEN]) {
  if (index >= OSDP_WEAK_KEY_COUNT) return false;

  // Three families of 256, matching the patterns Bishop Fox enumerate: a
  // single byte repeated, an ascending run, and a descending run, from every
  // possible starting byte.
  uint32_t family = index / 256;
  uint8_t start = (uint8_t)(index % 256);

  for (int i = 0; i < OSDP_KEY_LEN; i++) {
    switch (family) {
      case 0:
        key[i] = start;
        break;
      case 1:
        key[i] = (uint8_t)(start + i);
        break;
      default:
        key[i] = (uint8_t)(start - i);
        break;
    }
  }
  return true;
}
