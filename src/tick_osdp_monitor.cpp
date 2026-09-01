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
        // Authenticated but readable. Integrity without confidentiality still
        // leaves the credential on the wire.
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
    default:
      return "";
  }
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
