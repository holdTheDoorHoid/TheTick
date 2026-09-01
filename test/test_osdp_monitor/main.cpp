// Host-side tests for the OSDP threat monitor.
//
// Each of the Bishop Fox "Badge of Shame" attacks is replayed as a synthetic
// bus transcript and the monitor is asked what it saw. The test that matters
// as much as any detection is test_healthy_session_is_quiet: a detector that
// fires on a correctly configured bus is one an operator learns to ignore.

#include <unity.h>

#include <cstring>
#include <string>
#include <vector>

#include "../../src/tick_osdp_dissect.cpp"
#include "../../src/tick_osdp_monitor.cpp"

// --- transcript building ----------------------------------------------------

static std::vector<uint8_t> frame(uint8_t address, bool is_reply,
                                  uint8_t sequence, int scb_type, uint8_t id,
                                  const std::vector<uint8_t> &payload) {
  std::vector<uint8_t> p;
  p.push_back(OSDP_PKT_SOM);
  p.push_back((uint8_t)(address | (is_reply ? 0x80 : 0)));
  p.push_back(0);
  p.push_back(0);
  uint8_t control = (uint8_t)((sequence & 3) | 0x04);  // always CRC
  if (scb_type > 0) control |= 0x08;
  p.push_back(control);
  if (scb_type > 0) {
    p.push_back(2);
    p.push_back((uint8_t)scb_type);
  }
  p.push_back(id);
  for (uint8_t b : payload) p.push_back(b);

  size_t total = p.size() + 2;
  p[2] = (uint8_t)(total & 0xFF);
  p[3] = (uint8_t)(total >> 8);
  uint16_t crc = osdp_crc16(p.data(), p.size());
  p.push_back((uint8_t)(crc & 0xFF));
  p.push_back((uint8_t)(crc >> 8));
  return p;
}

// A PDCAP reply advertising communication security, or not.
static std::vector<uint8_t> pdcap(bool supports_crypto) {
  return {OSDP_PD_CAP_CONTACT_STATUS, 1, 4,
          OSDP_PD_CAP_OUTPUT_CONTROL, 1, 4,
          OSDP_PD_CAP_COMMUNICATION_SECURITY, (uint8_t)(supports_crypto ? 1 : 0), 1,
          OSDP_PD_CAP_READERS, 1, 1};
}

// --- harness ----------------------------------------------------------------

static std::vector<osdp_threat> fired;
static void on_threat(const osdp_threat_report *r, void *ctx) {
  (void)ctx;
  fired.push_back(r->threat);
}

static bool saw(osdp_threat t) {
  for (osdp_threat f : fired) {
    if (f == t) return true;
  }
  return false;
}

static osdp_monitor mon;

static void feed(const std::vector<uint8_t> &bytes) {
  osdp_monitor_feed_bytes(&mon, bytes.data(), bytes.size());
}

static uint8_t seq_of(int i) { return (uint8_t)((i % 3) + 1); }

void setUp(void) {
  fired.clear();
  osdp_monitor_init(&mon, on_threat, NULL);
}
void tearDown(void) {}

// --- Bishop Fox attack #1: passive eavesdropping -----------------------------

void test_detects_cleartext_session(void) {
  // A bus that just polls, forever, with no security block anywhere.
  for (int i = 0; i < 40; i++) {
    feed(frame(0x01, false, seq_of(i), 0, OSDP_CMD_POLL, {}));
    feed(frame(0x01, true, seq_of(i), 0, OSDP_REPLY_ACK, {}));
  }
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_CLEARTEXT_SESSION));
}

void test_detects_cleartext_card_read(void) {
  feed(frame(0x01, false, 1, 0, OSDP_CMD_POLL, {}));
  // A credential in a plain REPLY_RAW: readable by anyone on the pair.
  feed(frame(0x01, true, 1, 0, OSDP_REPLY_RAW,
             {0x00, 0x1A, 0x00, 0xC0, 0xFF, 0xEE}));
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_CLEARTEXT_CARD_READ));
}

// --- attack #2: downgrade ----------------------------------------------------

void test_detects_reader_advertising_no_crypto(void) {
  feed(frame(0x01, false, 1, 0, OSDP_CMD_CAP, {0x00}));
  feed(frame(0x01, true, 1, 0, OSDP_REPLY_PDCAP, pdcap(false)));
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_NO_CRYPTO_ADVERTISED));
}

// The strong signal: a reader that said it could do crypto, then said it
// could not. Readers do not change; something in the wire rewrote it.
void test_detects_capability_rewrite(void) {
  feed(frame(0x01, false, 1, 0, OSDP_CMD_CAP, {0x00}));
  feed(frame(0x01, true, 1, 0, OSDP_REPLY_PDCAP, pdcap(true)));
  TEST_ASSERT_FALSE(saw(OSDP_THREAT_CAPABILITY_CHANGED));

  feed(frame(0x01, false, 2, 0, OSDP_CMD_CAP, {0x00}));
  feed(frame(0x01, true, 2, 0, OSDP_REPLY_PDCAP, pdcap(false)));
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_CAPABILITY_CHANGED));
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_NO_CRYPTO_ADVERTISED));
}

// A session that was encrypted and then is not, which is what forcing a
// downgrade mid-conversation looks like.
void test_detects_security_regression(void) {
  feed(frame(0x01, false, 1, OSDP_SCS_11, OSDP_CMD_CHLNG, {1, 2, 3}));
  feed(frame(0x01, true, 1, OSDP_SCS_12, OSDP_REPLY_CCRYPT, {4, 5, 6}));
  feed(frame(0x01, false, 2, OSDP_SCS_17, OSDP_CMD_POLL, {0xAA}));
  TEST_ASSERT_FALSE(saw(OSDP_THREAT_SECURITY_REGRESSION));

  feed(frame(0x01, false, 3, 0, OSDP_CMD_POLL, {}));
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_SECURITY_REGRESSION));
}

// --- attacks #3 and #5: install mode and keyset capture ----------------------

void test_detects_key_on_the_wire(void) {
  feed(frame(0x01, false, 1, 0, OSDP_CMD_KEYSET,
             {0x01, 0x10, 1, 2, 3, 4, 5, 6, 7, 8}));
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_KEYSET_ON_WIRE));
  // One key install is commissioning, not necessarily install mode.
  TEST_ASSERT_FALSE(saw(OSDP_THREAT_INSTALL_MODE));
}

void test_detects_controller_stuck_in_install_mode(void) {
  for (int i = 0; i < 5; i++) {
    feed(frame(0x01, false, seq_of(i), 0, OSDP_CMD_KEYSET,
               {0x01, 0x10, 1, 2, 3, 4, 5, 6, 7, 8}));
  }
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_INSTALL_MODE));
}

// --- attack #4 groundwork: weak key candidates -------------------------------

void test_weak_key_candidates(void) {
  uint8_t key[OSDP_KEY_LEN];

  // Repeated single byte.
  TEST_ASSERT_TRUE(osdp_weak_key_candidate(0x04, key));
  for (int i = 0; i < OSDP_KEY_LEN; i++) TEST_ASSERT_EQUAL_HEX8(0x04, key[i]);

  // Ascending run.
  TEST_ASSERT_TRUE(osdp_weak_key_candidate(256 + 0x01, key));
  for (int i = 0; i < OSDP_KEY_LEN; i++) {
    TEST_ASSERT_EQUAL_HEX8((uint8_t)(0x01 + i), key[i]);
  }

  // Descending run.
  TEST_ASSERT_TRUE(osdp_weak_key_candidate(512 + 0x0A, key));
  for (int i = 0; i < OSDP_KEY_LEN; i++) {
    TEST_ASSERT_EQUAL_HEX8((uint8_t)(0x0A - i), key[i]);
  }

  // Bounds.
  TEST_ASSERT_TRUE(osdp_weak_key_candidate(OSDP_WEAK_KEY_COUNT - 1, key));
  TEST_ASSERT_FALSE(osdp_weak_key_candidate(OSDP_WEAK_KEY_COUNT, key));
  TEST_ASSERT_FALSE(osdp_weak_key_candidate(0xFFFFFFFF, key));
}

// The all-zero key is the one that turns up most often in sample code, so it
// had better be in the list.
void test_weak_key_list_contains_known_defaults(void) {
  uint8_t key[OSDP_KEY_LEN];
  bool found_zero = false, found_ff = false, found_ascending = false;

  for (uint32_t i = 0; i < OSDP_WEAK_KEY_COUNT; i++) {
    TEST_ASSERT_TRUE(osdp_weak_key_candidate(i, key));
    uint8_t zeros[OSDP_KEY_LEN] = {0};
    uint8_t ffs[OSDP_KEY_LEN];
    memset(ffs, 0xFF, sizeof(ffs));
    uint8_t asc[OSDP_KEY_LEN];
    for (int j = 0; j < OSDP_KEY_LEN; j++) asc[j] = (uint8_t)j;

    if (memcmp(key, zeros, OSDP_KEY_LEN) == 0) found_zero = true;
    if (memcmp(key, ffs, OSDP_KEY_LEN) == 0) found_ff = true;
    if (memcmp(key, asc, OSDP_KEY_LEN) == 0) found_ascending = true;
  }
  TEST_ASSERT_TRUE(found_zero);
  TEST_ASSERT_TRUE(found_ff);
  TEST_ASSERT_TRUE(found_ascending);
}

// --- other signals -----------------------------------------------------------

void test_detects_handshake_retry_storm(void) {
  for (int i = 0; i < 10; i++) {
    feed(frame(0x01, false, seq_of(i), OSDP_SCS_11, OSDP_CMD_CHLNG, {1, 2, 3}));
    feed(frame(0x01, true, seq_of(i), OSDP_SCS_12, OSDP_REPLY_CCRYPT, {4, 5}));
  }
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_SC_RETRY_STORM));
}

void test_detects_sequence_anomaly(void) {
  feed(frame(0x01, false, 1, 0, OSDP_CMD_POLL, {}));
  // Skipping a number outright is what an injected frame looks like.
  feed(frame(0x01, false, 3, 0, OSDP_CMD_POLL, {}));
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_SEQUENCE_ANOMALY));
}

// A secure channel handshake restarts the sequence at 1, and a peripheral
// that reboots does the same. Neither is an attack.
void test_sequence_restart_is_not_an_anomaly(void) {
  feed(frame(0x01, false, 1, 0, OSDP_CMD_POLL, {}));
  feed(frame(0x01, false, 2, 0, OSDP_CMD_POLL, {}));
  feed(frame(0x01, false, 1, OSDP_SCS_11, OSDP_CMD_CHLNG, {1, 2, 3}));
  TEST_ASSERT_FALSE(saw(OSDP_THREAT_SEQUENCE_ANOMALY));
}

// A retransmission after a missed reply repeats the number, which is normal
// on a long cable.
void test_sequence_retransmit_is_not_an_anomaly(void) {
  feed(frame(0x01, false, 1, 0, OSDP_CMD_POLL, {}));
  feed(frame(0x01, false, 1, 0, OSDP_CMD_POLL, {}));
  feed(frame(0x01, false, 2, 0, OSDP_CMD_POLL, {}));
  TEST_ASSERT_FALSE(saw(OSDP_THREAT_SEQUENCE_ANOMALY));
}

// --- the one that keeps the detector trustworthy -----------------------------

// A correctly configured bus: a short cleartext startup, a handshake, then
// encrypted traffic forever. Nothing here may raise anything.
void test_healthy_session_is_quiet(void) {
  // Discovery, in the clear, exactly as a real controller does it.
  feed(frame(0x01, false, 1, 0, OSDP_CMD_POLL, {}));
  feed(frame(0x01, true, 1, 0, OSDP_REPLY_ACK, {}));
  feed(frame(0x01, false, 2, 0, OSDP_CMD_ID, {0x00}));
  feed(frame(0x01, true, 2, 0, OSDP_REPLY_PDID, {1, 2, 3, 4, 5, 6, 7, 8}));
  feed(frame(0x01, false, 3, 0, OSDP_CMD_CAP, {0x00}));
  feed(frame(0x01, true, 3, 0, OSDP_REPLY_PDCAP, pdcap(true)));

  // Secure channel handshake.
  feed(frame(0x01, false, 1, OSDP_SCS_11, OSDP_CMD_CHLNG, {1, 2, 3, 4, 5, 6, 7, 8}));
  feed(frame(0x01, true, 1, OSDP_SCS_12, OSDP_REPLY_CCRYPT, {1, 2, 3, 4}));
  feed(frame(0x01, false, 2, OSDP_SCS_13, OSDP_CMD_SCRYPT, {1, 2, 3, 4}));
  feed(frame(0x01, true, 2, OSDP_SCS_14, OSDP_REPLY_RMAC_I, {1, 2, 3, 4}));

  // Then a long encrypted conversation, including credentials.
  for (int i = 0; i < 200; i++) {
    feed(frame(0x01, false, seq_of(i), OSDP_SCS_17, OSDP_CMD_POLL, {0xAA, 0xBB}));
    uint8_t reply = (i % 20 == 0) ? OSDP_REPLY_RAW : OSDP_REPLY_ACK;
    feed(frame(0x01, true, seq_of(i), OSDP_SCS_18, reply, {0xCC, 0xDD, 0xEE}));
  }

  if (!fired.empty()) {
    std::string msg = "healthy bus raised: ";
    for (osdp_threat t : fired) {
      msg += osdp_threat_name(t);
      msg += " ";
    }
    TEST_FAIL_MESSAGE(msg.c_str());
  }
}

// Frames that fail their own CRC must not drive findings, or noise on a long
// cable becomes a stream of false alarms.
void test_corrupt_frames_do_not_raise_findings(void) {
  std::vector<uint8_t> f = frame(0x01, true, 1, 0, OSDP_REPLY_RAW,
                                 {0x00, 0x1A, 0x00, 0xC0, 0xFF, 0xEE});
  for (int i = 0; i < 50; i++) {
    std::vector<uint8_t> bad = f;
    bad[bad.size() - 1] ^= (uint8_t)(i + 1);
    feed(bad);
  }
  TEST_ASSERT_TRUE(fired.empty());
  TEST_ASSERT_TRUE(mon.frames_bad > 0);
}

void test_reports_deduplicate_until_rearmed(void) {
  for (int i = 0; i < 20; i++) {
    feed(frame(0x01, false, seq_of(i), 0, OSDP_CMD_KEYSET, {1, 2, 3}));
  }
  int first = 0;
  for (osdp_threat t : fired) {
    if (t == OSDP_THREAT_KEYSET_ON_WIRE) first++;
  }
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, first, "should report once, not per frame");
  TEST_ASSERT_TRUE(mon.threat_counts[OSDP_THREAT_KEYSET_ON_WIRE] > 1);

  osdp_monitor_rearm(&mon);
  feed(frame(0x01, false, 1, 0, OSDP_CMD_KEYSET, {1, 2, 3}));
  int second = 0;
  for (osdp_threat t : fired) {
    if (t == OSDP_THREAT_KEYSET_ON_WIRE) second++;
  }
  TEST_ASSERT_EQUAL_INT(2, second);
}

// The monitor consumes bytes off a UART, so it has to cope with frames split
// across reads and with a bus it joined mid-conversation.
void test_handles_split_and_noisy_streams(void) {
  std::vector<uint8_t> stream;
  stream.insert(stream.end(), {0x00, 0xFF, 0x12});  // joined mid-frame
  for (int i = 0; i < 30; i++) {
    std::vector<uint8_t> f =
        frame(0x01, false, seq_of(i), 0, OSDP_CMD_POLL, {});
    stream.insert(stream.end(), f.begin(), f.end());
  }

  // Deliver in small, awkward chunks, keeping any unconsumed tail.
  std::vector<uint8_t> pending;
  for (size_t i = 0; i < stream.size(); i += 7) {
    size_t n = std::min<size_t>(7, stream.size() - i);
    pending.insert(pending.end(), stream.begin() + i, stream.begin() + i + n);
    size_t used = osdp_monitor_feed_bytes(&mon, pending.data(), pending.size());
    TEST_ASSERT_TRUE(used <= pending.size());
    pending.erase(pending.begin(), pending.begin() + used);
  }

  TEST_ASSERT_TRUE_MESSAGE(mon.frames_seen >= 25,
                           "most frames should survive chunked delivery");
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_CLEARTEXT_SESSION));
}

void test_tracks_multiple_peers_independently(void) {
  for (int i = 0; i < 30; i++) {
    // Address 1 is encrypted and healthy.
    feed(frame(0x01, false, seq_of(i), OSDP_SCS_17, OSDP_CMD_POLL, {0xAA}));
    // Address 2 is in the clear.
    feed(frame(0x02, false, seq_of(i), 0, OSDP_CMD_POLL, {}));
  }
  TEST_ASSERT_TRUE(saw(OSDP_THREAT_CLEARTEXT_SESSION));

  // The healthy peer must not have been marked cleartext.
  for (int i = 0; i < OSDP_MONITOR_MAX_PEERS; i++) {
    if (mon.peers[i].in_use && mon.peers[i].address == 0x01) {
      TEST_ASSERT_TRUE(mon.peers[i].saw_secure_data);
      TEST_ASSERT_EQUAL_UINT16(0, mon.peers[i].cleartext_frames);
    }
  }
}

void test_threat_names_and_descriptions_present(void) {
  for (int t = OSDP_THREAT_NONE + 1; t < OSDP_THREAT_COUNT; t++) {
    const char *name = osdp_threat_name((osdp_threat)t);
    const char *desc = osdp_threat_description((osdp_threat)t);
    TEST_ASSERT_TRUE(name != NULL && strlen(name) > 0);
    TEST_ASSERT_TRUE(desc != NULL && strlen(desc) > 0);
    TEST_ASSERT_NOT_EQUAL(0, strcmp(name, "none"));
  }
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_detects_cleartext_session);
  RUN_TEST(test_detects_cleartext_card_read);
  RUN_TEST(test_detects_reader_advertising_no_crypto);
  RUN_TEST(test_detects_capability_rewrite);
  RUN_TEST(test_detects_security_regression);
  RUN_TEST(test_detects_key_on_the_wire);
  RUN_TEST(test_detects_controller_stuck_in_install_mode);
  RUN_TEST(test_weak_key_candidates);
  RUN_TEST(test_weak_key_list_contains_known_defaults);
  RUN_TEST(test_detects_handshake_retry_storm);
  RUN_TEST(test_detects_sequence_anomaly);
  RUN_TEST(test_sequence_restart_is_not_an_anomaly);
  RUN_TEST(test_sequence_retransmit_is_not_an_anomaly);
  RUN_TEST(test_healthy_session_is_quiet);
  RUN_TEST(test_corrupt_frames_do_not_raise_findings);
  RUN_TEST(test_reports_deduplicate_until_rearmed);
  RUN_TEST(test_handles_split_and_noisy_streams);
  RUN_TEST(test_tracks_multiple_peers_independently);
  RUN_TEST(test_threat_names_and_descriptions_present);
  return UNITY_END();
}
