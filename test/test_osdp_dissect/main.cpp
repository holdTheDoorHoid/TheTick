// Host-side tests for the passive OSDP frame dissector.
//
// This parser reads attacker-reachable bytes off a wire, so the bar is higher
// than "does it decode a good frame". It must also never read outside its
// buffer, never accept a frame whose trailer does not verify, and never
// wedge on noise. The fuzz cases below are run under AddressSanitizer in CI.

#include <unity.h>

#include <cstring>
#include <random>
#include <vector>

#include "../../src/tick_osdp_dissect.cpp"

// --- an independent frame builder ------------------------------------------
//
// Deliberately written from the specification rather than by reusing anything
// in the dissector, so that a mistake in one is not mirrored in the other.

struct BuiltFrame {
  std::vector<uint8_t> bytes;
};

static BuiltFrame build_frame(uint8_t address, bool is_reply, uint8_t sequence,
                              bool use_crc, int scb_type,
                              const std::vector<uint8_t> &scb_extra, uint8_t id,
                              const std::vector<uint8_t> &payload,
                              bool with_mark = false) {
  std::vector<uint8_t> p;

  p.push_back(OSDP_PKT_SOM);
  p.push_back((uint8_t)(address | (is_reply ? 0x80 : 0x00)));
  p.push_back(0);  // length placeholder
  p.push_back(0);

  uint8_t control = (uint8_t)(sequence & 0x03);
  if (use_crc) control |= 0x04;
  if (scb_type > 0) control |= 0x08;
  p.push_back(control);

  if (scb_type > 0) {
    uint8_t scb_len = (uint8_t)(2 + scb_extra.size());
    p.push_back(scb_len);
    p.push_back((uint8_t)scb_type);
    for (uint8_t b : scb_extra) p.push_back(b);
  }

  p.push_back(id);
  for (uint8_t b : payload) p.push_back(b);

  size_t total = p.size() + (use_crc ? 2 : 1);
  p[2] = (uint8_t)(total & 0xFF);
  p[3] = (uint8_t)((total >> 8) & 0xFF);

  if (use_crc) {
    uint16_t crc = osdp_crc16(p.data(), p.size());
    p.push_back((uint8_t)(crc & 0xFF));
    p.push_back((uint8_t)(crc >> 8));
  } else {
    p.push_back(osdp_checksum(p.data(), p.size()));
  }

  BuiltFrame f;
  if (with_mark) f.bytes.push_back(OSDP_PKT_MARK);
  f.bytes.insert(f.bytes.end(), p.begin(), p.end());
  return f;
}

// --- CRC ground truth -------------------------------------------------------

// OSDP uses CRC-16/AUG-CCITT: polynomial 0x1021, initial value 0x1D0F, no
// reflection. The catalogue check value for the string "123456789" is 0xE5CC.
// Asserting against a published constant catches a transcription error that a
// round-trip test against our own builder never would.
void test_crc_matches_published_check_value(void) {
  const char *s = "123456789";
  TEST_ASSERT_EQUAL_HEX16(0xE5CC, osdp_crc16((const uint8_t *)s, 9));
}

void test_checksum_is_twos_complement(void) {
  uint8_t buf[] = {0x53, 0x00, 0x08, 0x00, 0x00, 0x60};
  uint8_t sum = 0;
  for (uint8_t b : buf) sum = (uint8_t)(sum + b);
  TEST_ASSERT_EQUAL_HEX8((uint8_t)(-sum), osdp_checksum(buf, sizeof(buf)));
}

// --- well formed frames -----------------------------------------------------

void test_parses_poll(void) {
  BuiltFrame f = build_frame(0x65, false, 1, true, 0, {}, OSDP_CMD_POLL, {});

  osdp_frame out;
  size_t used = 0;
  TEST_ASSERT_EQUAL_INT(OSDP_DISSECT_OK,
                        osdp_dissect(f.bytes.data(), f.bytes.size(), &out, &used));
  TEST_ASSERT_EQUAL_UINT8(0x65, out.address);
  TEST_ASSERT_FALSE(out.is_reply);
  TEST_ASSERT_EQUAL_UINT8(1, out.sequence);
  TEST_ASSERT_TRUE(out.uses_crc);
  TEST_ASSERT_FALSE(out.has_scb);
  TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, out.id);
  TEST_ASSERT_EQUAL_UINT16(0, out.payload_len);
  TEST_ASSERT_TRUE(out.trailer_valid);
  TEST_ASSERT_EQUAL_UINT32(f.bytes.size(), used);
  TEST_ASSERT_EQUAL_STRING("POLL", osdp_frame_name(&out));
}

void test_parses_reply_with_payload(void) {
  std::vector<uint8_t> raw = {0x01, 0x1A, 0x00, 0xAB, 0xCD, 0xEF};
  BuiltFrame f = build_frame(0x7F, true, 2, true, 0, {}, OSDP_REPLY_RAW, raw);

  osdp_frame out;
  TEST_ASSERT_EQUAL_INT(OSDP_DISSECT_OK,
                        osdp_dissect(f.bytes.data(), f.bytes.size(), &out, NULL));
  TEST_ASSERT_TRUE(out.is_reply);
  TEST_ASSERT_EQUAL_UINT8(0x7F, out.address);  // reply flag stripped
  TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_RAW, out.id);
  TEST_ASSERT_EQUAL_UINT16(raw.size(), out.payload_len);
  TEST_ASSERT_EQUAL_MEMORY(raw.data(), out.payload, raw.size());
  TEST_ASSERT_EQUAL_STRING("RAW", osdp_frame_name(&out));
}

void test_parses_checksum_frames(void) {
  BuiltFrame f = build_frame(0x01, false, 0, false, 0, {}, OSDP_CMD_ID, {0x00});
  osdp_frame out;
  TEST_ASSERT_EQUAL_INT(OSDP_DISSECT_OK,
                        osdp_dissect(f.bytes.data(), f.bytes.size(), &out, NULL));
  TEST_ASSERT_FALSE(out.uses_crc);
  TEST_ASSERT_TRUE(out.trailer_valid);
}

void test_parses_mark_byte(void) {
  BuiltFrame f =
      build_frame(0x02, false, 0, true, 0, {}, OSDP_CMD_POLL, {}, true);
  osdp_frame out;
  size_t used = 0;
  TEST_ASSERT_EQUAL_INT(OSDP_DISSECT_OK,
                        osdp_dissect(f.bytes.data(), f.bytes.size(), &out, &used));
  TEST_ASSERT_TRUE(out.has_mark);
  TEST_ASSERT_EQUAL_UINT32(f.bytes.size(), used);
}

// The security block is what tells a listener whether the conversation is
// actually protected, so each type has to be classified correctly.
void test_security_block_classification(void) {
  struct {
    int scs;
    bool encrypted;
  } cases[] = {
      {OSDP_SCS_11, false}, {OSDP_SCS_12, false}, {OSDP_SCS_13, false},
      {OSDP_SCS_14, false}, {OSDP_SCS_15, false}, {OSDP_SCS_16, false},
      {OSDP_SCS_17, true},  {OSDP_SCS_18, true},
  };

  for (auto &c : cases) {
    BuiltFrame f = build_frame(0x01, false, 1, true, c.scs, {0x00, 0x00},
                               OSDP_CMD_POLL, {});
    osdp_frame out;
    TEST_ASSERT_EQUAL_INT(
        OSDP_DISSECT_OK,
        osdp_dissect(f.bytes.data(), f.bytes.size(), &out, NULL));
    TEST_ASSERT_TRUE(out.has_scb);
    TEST_ASSERT_EQUAL_HEX8(c.scs, out.scb_type);
    TEST_ASSERT_EQUAL_UINT8(2, out.scb_data_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(c.encrypted, out.payload_encrypted,
                                  "wrong encryption classification");
  }
}

// --- malformed and hostile input --------------------------------------------

void test_rejects_bad_trailer(void) {
  BuiltFrame f = build_frame(0x01, false, 0, true, 0, {}, OSDP_CMD_POLL, {});
  f.bytes[f.bytes.size() - 1] ^= 0xFF;

  osdp_frame out;
  TEST_ASSERT_EQUAL_INT(OSDP_DISSECT_BAD_TRAILER,
                        osdp_dissect(f.bytes.data(), f.bytes.size(), &out, NULL));
  TEST_ASSERT_FALSE(out.trailer_valid);
}

void test_rejects_impossible_lengths(void) {
  osdp_frame out;

  // Declared length shorter than a header can possibly be. The subtraction
  // that computes payload length would wrap if this were not caught first.
  uint8_t tiny[] = {0x53, 0x01, 0x02, 0x00, 0x04, 0x60, 0x00, 0x00};
  TEST_ASSERT_EQUAL_INT(OSDP_DISSECT_BAD_LENGTH,
                        osdp_dissect(tiny, sizeof(tiny), &out, NULL));

  // Zero length.
  uint8_t zero[] = {0x53, 0x01, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00};
  TEST_ASSERT_EQUAL_INT(OSDP_DISSECT_BAD_LENGTH,
                        osdp_dissect(zero, sizeof(zero), &out, NULL));

  // Absurdly large.
  uint8_t huge[] = {0x53, 0x01, 0xFF, 0xFF, 0x04, 0x60, 0x00, 0x00};
  TEST_ASSERT_EQUAL_INT(OSDP_DISSECT_BAD_LENGTH,
                        osdp_dissect(huge, sizeof(huge), &out, NULL));
}

void test_rejects_security_block_running_past_frame(void) {
  BuiltFrame f =
      build_frame(0x01, false, 1, true, OSDP_SCS_17, {0x00, 0x00}, OSDP_CMD_POLL, {});
  // Claim a security block far longer than the frame.
  f.bytes[OSDP_HEADER_LEN] = 0xFF;

  osdp_frame out;
  TEST_ASSERT_EQUAL_INT(OSDP_DISSECT_BAD_SCB,
                        osdp_dissect(f.bytes.data(), f.bytes.size(), &out, NULL));

  // And a security block too short to contain its own header.
  f.bytes[OSDP_HEADER_LEN] = 0x01;
  TEST_ASSERT_EQUAL_INT(OSDP_DISSECT_BAD_SCB,
                        osdp_dissect(f.bytes.data(), f.bytes.size(), &out, NULL));
}

void test_truncated_frames_ask_for_more(void) {
  BuiltFrame f = build_frame(0x01, false, 0, true, 0, {}, OSDP_REPLY_PDCAP,
                             {1, 2, 3, 4, 5, 6});

  osdp_frame out;
  for (size_t n = 1; n < f.bytes.size(); n++) {
    osdp_dissect_result r = osdp_dissect(f.bytes.data(), n, &out, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(OSDP_DISSECT_NEED_MORE, r,
                                  "a truncated frame must not parse");
  }
  TEST_ASSERT_EQUAL_INT(
      OSDP_DISSECT_OK,
      osdp_dissect(f.bytes.data(), f.bytes.size(), &out, NULL));
}

// A listener joins a live bus mid-conversation, so leading garbage is normal.
void test_stream_resynchronises(void) {
  BuiltFrame f = build_frame(0x09, true, 3, true, 0, {}, OSDP_REPLY_ACK, {});

  std::vector<uint8_t> stream = {0x00, 0xAA, 0x53, 0x12, 0xFF, 0x99};
  size_t noise = stream.size();
  stream.insert(stream.end(), f.bytes.begin(), f.bytes.end());

  osdp_frame out;
  size_t off = 0, used = 0;
  TEST_ASSERT_EQUAL_INT(
      OSDP_DISSECT_OK,
      osdp_dissect_stream(stream.data(), stream.size(), &out, &off, &used));
  TEST_ASSERT_EQUAL_UINT32(noise, off);
  TEST_ASSERT_EQUAL_UINT32(f.bytes.size(), used);
  TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, out.id);
}

void test_stream_reports_no_frame_in_noise(void) {
  std::vector<uint8_t> noise = {0x00, 0x11, 0x22, 0x33, 0x44};
  osdp_frame out;
  size_t off = 0, used = 0;
  osdp_dissect_result r =
      osdp_dissect_stream(noise.data(), noise.size(), &out, &off, &used);
  TEST_ASSERT_NOT_EQUAL(OSDP_DISSECT_OK, r);
  TEST_ASSERT_EQUAL_UINT32(0, used);
}

// Every byte of a valid frame flipped, one at a time. Nothing may be reported
// as a good frame unless the trailer genuinely still verifies, and nothing may
// read out of bounds - AddressSanitizer is the real assertion here.
void test_single_bit_corruption_never_yields_false_positive(void) {
  BuiltFrame good = build_frame(0x11, true, 1, true, OSDP_SCS_16, {0, 0},
                                OSDP_REPLY_RAW, {1, 2, 3, 4});

  for (size_t i = 0; i < good.bytes.size(); i++) {
    for (int bit = 0; bit < 8; bit++) {
      std::vector<uint8_t> bad = good.bytes;
      bad[i] ^= (uint8_t)(1 << bit);

      osdp_frame out;
      size_t used = 0;
      osdp_dissect_result r = osdp_dissect(bad.data(), bad.size(), &out, &used);
      if (r == OSDP_DISSECT_OK) {
        // Only legitimate if the trailer really does verify over the
        // corrupted bytes, which the dissector must have checked itself.
        TEST_ASSERT_TRUE(out.trailer_valid);
      }
    }
  }
}

// Random bytes, long runs. Under AddressSanitizer this is the test that
// matters most: a dissector reading a hostile bus must not walk off its
// buffer for any input at all.
void test_fuzz_never_reads_out_of_bounds(void) {
  std::mt19937 rng(0xC0FFEE);

  for (int iter = 0; iter < 20000; iter++) {
    size_t n = 1 + (rng() % 64);
    std::vector<uint8_t> buf(n);
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(rng() & 0xFF);

    // Bias towards buffers that look like frames, so the parser is actually
    // entered rather than bailing at the first byte.
    if (iter % 2 == 0) buf[0] = OSDP_PKT_SOM;
    if (iter % 5 == 0 && n > 1) {
      buf[0] = OSDP_PKT_MARK;
      buf[1] = OSDP_PKT_SOM;
    }

    osdp_frame out;
    size_t used = 0;
    osdp_dissect_result r = osdp_dissect(buf.data(), n, &out, &used);
    if (r == OSDP_DISSECT_OK) {
      TEST_ASSERT_TRUE(used <= n);
      TEST_ASSERT_TRUE(out.payload_len <= n);
      // Payload must lie inside the buffer we handed over.
      TEST_ASSERT_TRUE(out.payload >= buf.data());
      TEST_ASSERT_TRUE(out.payload + out.payload_len <= buf.data() + n);
    }

    size_t off = 0;
    osdp_dissect_stream(buf.data(), n, &out, &off, &used);
    TEST_ASSERT_TRUE(off <= n);
  }
}

// The stream scanner must always make progress, whatever it is fed, or a
// device on a noisy bus locks up.
void test_stream_always_terminates(void) {
  std::mt19937 rng(99);
  for (int iter = 0; iter < 5000; iter++) {
    size_t n = 1 + (rng() % 128);
    std::vector<uint8_t> buf(n);
    for (size_t i = 0; i < n; i++) {
      // Heavy on SOM and MARK, the bytes that drive the scanner.
      uint32_t r = rng() % 3;
      buf[i] = r == 0 ? OSDP_PKT_SOM : (r == 1 ? OSDP_PKT_MARK : (uint8_t)rng());
    }
    osdp_frame out;
    size_t off = 0, used = 0;
    osdp_dissect_stream(buf.data(), n, &out, &off, &used);
    TEST_ASSERT_TRUE(off <= n);
    TEST_ASSERT_TRUE(used <= n);
  }
}

void test_command_and_reply_names(void) {
  TEST_ASSERT_EQUAL_STRING("KEYSET", osdp_command_name(OSDP_CMD_KEYSET));
  TEST_ASSERT_EQUAL_STRING("CHLNG", osdp_command_name(OSDP_CMD_CHLNG));
  TEST_ASSERT_EQUAL_STRING("XWR", osdp_command_name(OSDP_CMD_XWR));
  TEST_ASSERT_EQUAL_STRING("PDCAP", osdp_reply_name(OSDP_REPLY_PDCAP));
  TEST_ASSERT_EQUAL_STRING("CCRYPT", osdp_reply_name(OSDP_REPLY_CCRYPT));
  TEST_ASSERT_EQUAL_STRING("XRD", osdp_reply_name(OSDP_REPLY_XRD));
  TEST_ASSERT_EQUAL_STRING("UNKNOWN", osdp_command_name(0x00));
}

void setUp(void) {}
void tearDown(void) {}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_crc_matches_published_check_value);
  RUN_TEST(test_checksum_is_twos_complement);
  RUN_TEST(test_parses_poll);
  RUN_TEST(test_parses_reply_with_payload);
  RUN_TEST(test_parses_checksum_frames);
  RUN_TEST(test_parses_mark_byte);
  RUN_TEST(test_security_block_classification);
  RUN_TEST(test_rejects_bad_trailer);
  RUN_TEST(test_rejects_impossible_lengths);
  RUN_TEST(test_rejects_security_block_running_past_frame);
  RUN_TEST(test_truncated_frames_ask_for_more);
  RUN_TEST(test_stream_resynchronises);
  RUN_TEST(test_stream_reports_no_frame_in_noise);
  RUN_TEST(test_single_bit_corruption_never_yields_false_positive);
  RUN_TEST(test_fuzz_never_reads_out_of_bounds);
  RUN_TEST(test_stream_always_terminates);
  RUN_TEST(test_command_and_reply_names);
  return UNITY_END();
}
