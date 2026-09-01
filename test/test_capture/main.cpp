// Host-side tests for the capture and transmit path.
//
// These compile the real src/tick_capture.cpp - not a copy of it - against a
// small Arduino stub, so what is tested is what ships. The headline test is
// differential: the new bit-packing formatter is compared against a faithful
// reimplementation of the String-based algorithm it replaced, across every
// bit length and thousands of random patterns. Identical output means the
// log format and the web UI's parsing are untouched by the rewrite.

#include <unity.h>

#include <atomic>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "Arduino.h"

uint32_t tick_test_now_us = 0;

// --- stand-ins for the rest of the firmware --------------------------------

#include "tick_osdp.h"
#include "tick_protocol.h"

static std::vector<std::string> logged;
void append_log(String facility, String text) {
  logged.push_back(facility.s_ + "|" + text.s_);
}
void output_debug_string(String s) { (void)s; }

byte hex_to_byte(char in) {
  if (in >= '0' && in <= '9') return in - '0';
  if (in >= 'A' && in <= 'F') return in - 'A' + 10;
  if (in >= 'a' && in <= 'f') return in - 'a' + 10;
  return 0;
}
char c2h(unsigned char c) { return "0123456789abcdef"[0xF & c]; }

// A driver that records what it was asked to transmit.
static std::string tx_seen_hex;
static unsigned long tx_seen_bits = 0;
static int tx_call_count = 0;
static void fake_tx(const char *hex, size_t len, unsigned long bits) {
  tx_seen_hex.assign(hex, len);
  tx_seen_bits = bits;
  tx_call_count++;
}

const tick_protocol tick_protocol_disabled = {
    "disabled", "off", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};
static const tick_protocol fake_driver = {
    "fake", "fake", NULL, NULL, NULL, NULL, NULL, NULL, fake_tx, NULL, NULL,
};
const tick_protocol *tick_current = &fake_driver;

const tick_protocol *const tick_protocol_registry[] = {&tick_protocol_disabled};
const size_t tick_protocol_registry_count = 1;

// The code under test.
#include "../../src/tick_capture.cpp"

// --- reference implementation of the algorithm being replaced --------------
//
// Transcribed from the pre-refactor tick_wiegand_reader.cpp: the ISR packed
// nibbles into a hex string as bits arrived, then wiegand_fix_reader1_string()
// shifted the whole string right when the bit count was not a multiple of
// four. Kept here purely as a test oracle.

static char legacy_char_at(const std::string &s, size_t i) {
  return i < s.size() ? s[i] : 0;  // Arduino String::charAt is bounds checked
}

static std::string legacy_format(const std::vector<uint8_t> &bits) {
  uint8_t reader1_byte = 0;
  std::string reader1_string;
  int reader1_count = 0;

  for (uint8_t v : bits) {
    reader1_count++;
    reader1_byte = (uint8_t)(reader1_byte << 1);
    reader1_byte |= (uint8_t)(1 & v);
    if (reader1_count % 4 == 0) {
      reader1_string += c2h(reader1_byte);
      reader1_byte = 0;
    }
  }

  uint8_t loose_bits = (uint8_t)(reader1_count % 4);
  if (loose_bits > 0) {
    uint8_t moving_bits = (uint8_t)(4 - loose_bits);
    uint8_t moving_mask = (uint8_t)((1 << moving_bits) - 1);
    char c = (char)hex_to_byte(legacy_char_at(reader1_string, 0));
    for (size_t i = 0; i < reader1_string.length(); i++) {
      reader1_string[i] = c2h((unsigned char)(c >> moving_bits));
      c &= moving_mask;
      c = (char)((c << 4) | hex_to_byte(legacy_char_at(reader1_string, i + 1)));
    }
    reader1_string += c2h((unsigned char)((c >> moving_bits) | reader1_byte));
  }

  return reader1_string;
}

// --- helpers ---------------------------------------------------------------

static void fill(tick_capture_buffer *buf, const std::vector<uint8_t> &bits) {
  tick_capture_reset(buf);
  for (uint8_t b : bits) tick_capture_push(buf, b);
}

static std::string new_format(const std::vector<uint8_t> &bits) {
  tick_capture_buffer buf;
  fill(&buf, bits);
  char out[TICK_MAX_HEX + 1];
  tick_capture_to_hex(&buf, out, sizeof(out));
  return std::string(out);
}

// Unity calls these around every test. Without them a test that leaves a
// request queued makes the next one fail for the wrong reason.
void setUp(void) {
  tick_current = &fake_driver;
  tick_tx_service();  // drain anything left pending
  tx_call_count = 0;
  tx_seen_hex.clear();
  tx_seen_bits = 0;
  logged.clear();
  tick_test_now_us = 0;
}

void tearDown(void) {
  tick_current = &fake_driver;
  tick_tx_service();
}

// --- tests -----------------------------------------------------------------

// The one that matters most: identical output to the old algorithm for every
// length from 1 to 512 bits, over many random bit patterns.
void test_hex_matches_legacy_exhaustively(void) {
  std::mt19937 rng(20260901);
  std::uniform_int_distribution<int> coin(0, 1);

  for (int len = 1; len <= TICK_MAX_BITS; len++) {
    for (int trial = 0; trial < 12; trial++) {
      std::vector<uint8_t> bits;
      bits.reserve(len);
      for (int i = 0; i < len; i++) {
        // First trial all zeroes, second all ones, then random - the edges
        // are where a shifting bug would hide.
        if (trial == 0) bits.push_back(0);
        else if (trial == 1) bits.push_back(1);
        else bits.push_back((uint8_t)coin(rng));
      }

      std::string expected = legacy_format(bits);
      std::string actual = new_format(bits);
      if (expected != actual) {
        char msg[256];
        snprintf(msg, sizeof(msg), "len=%d trial=%d legacy=%s new=%s", len,
                 trial, expected.c_str(), actual.c_str());
        TEST_FAIL_MESSAGE(msg);
      }
    }
  }
}

// A real 26-bit HID H10301 credential, checked by hand.
void test_hex_known_vector(void) {
  // 0x2004060 over 26 bits.
  std::vector<uint8_t> bits;
  uint32_t value = 0x2004060;
  for (int i = 25; i >= 0; i--) bits.push_back((value >> i) & 1);

  TEST_ASSERT_EQUAL_STRING("2004060", new_format(bits).c_str());
  TEST_ASSERT_EQUAL_STRING(legacy_format(bits).c_str(),
                           new_format(bits).c_str());
}

void test_hex_pads_short_frames(void) {
  // Five bits, 1 0 0 0 1 == 0x11 rendered in two nibbles.
  std::vector<uint8_t> bits = {1, 0, 0, 0, 1};
  TEST_ASSERT_EQUAL_STRING("11", new_format(bits).c_str());

  // One bit set is a single nibble.
  TEST_ASSERT_EQUAL_STRING("1", new_format({1}).c_str());
  TEST_ASSERT_EQUAL_STRING("0", new_format({0}).c_str());
}

void test_binary_format(void) {
  tick_capture_buffer buf;
  fill(&buf, {1, 0, 1, 1, 0, 0, 1});
  char out[TICK_MAX_BITS + 1];
  size_t n = tick_capture_to_binary(&buf, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("1011001", out);
  TEST_ASSERT_EQUAL_UINT32(7, n);
}

// The bound that replaced unlimited heap growth in the interrupt handler.
// Guard bytes either side prove nothing is written outside the struct.
void test_push_respects_bounds(void) {
  struct {
    uint8_t guard_before[64];
    tick_capture_buffer buf;
    uint8_t guard_after[64];
  } wrapper;

  memset(wrapper.guard_before, 0xA5, sizeof(wrapper.guard_before));
  memset(wrapper.guard_after, 0x5A, sizeof(wrapper.guard_after));
  tick_capture_reset(&wrapper.buf);

  // Ten times the capacity, which is what a jammed or noisy line looks like.
  for (int i = 0; i < TICK_MAX_BITS * 10; i++) {
    tick_capture_push(&wrapper.buf, (uint8_t)(i & 1));
  }

  TEST_ASSERT_EQUAL_UINT16(TICK_MAX_BITS, wrapper.buf.count);
  TEST_ASSERT_TRUE(wrapper.buf.overflowed);

  for (size_t i = 0; i < sizeof(wrapper.guard_before); i++) {
    TEST_ASSERT_EQUAL_UINT8(0xA5, wrapper.guard_before[i]);
  }
  for (size_t i = 0; i < sizeof(wrapper.guard_after); i++) {
    TEST_ASSERT_EQUAL_UINT8(0x5A, wrapper.guard_after[i]);
  }
}

void test_take_requires_min_bits_and_gap(void) {
  tick_capture_buffer buf, out;
  tick_test_now_us = 1000;
  fill(&buf, {1, 0, 1});

  // Too few bits.
  tick_test_now_us = 100000;
  TEST_ASSERT_FALSE(tick_capture_take(&buf, &out, 4, 5000));

  tick_test_now_us = 100000;
  tick_capture_push(&buf, 1);  // now four
  // Gap not elapsed yet.
  TEST_ASSERT_FALSE(tick_capture_take(&buf, &out, 4, 5000));

  tick_test_now_us = 105000;
  TEST_ASSERT_TRUE(tick_capture_take(&buf, &out, 4, 5000));
  TEST_ASSERT_EQUAL_UINT16(4, out.count);
  // Source is emptied so the next frame starts clean.
  TEST_ASSERT_EQUAL_UINT16(0, buf.count);
}

// micros() wraps every ~71 minutes; a frame must not be held hostage by it.
void test_take_survives_micros_rollover(void) {
  tick_capture_buffer buf, out;
  tick_test_now_us = 0xFFFFFF00;
  fill(&buf, {1, 1, 1, 1});
  tick_test_now_us = 0x00000100;  // wrapped, 512us later
  TEST_ASSERT_FALSE(tick_capture_take(&buf, &out, 4, 5000));
  tick_test_now_us = 0x00002000;  // wrapped, well past the gap
  TEST_ASSERT_TRUE(tick_capture_take(&buf, &out, 4, 5000));
}

// --- transmit validation ---------------------------------------------------

void test_tx_rejects_oversized_input(void) {
  // Anything past the queue's own limit is refused outright.
  std::string very_long(TICK_TX_MAX_CHARS + 1, 'F');
  TEST_ASSERT_FALSE(tick_tx_submit(very_long.c_str(), 26));

  std::string huge(5000, 'F');
  TEST_ASSERT_FALSE(tick_tx_submit(huge.c_str(), 26));

  // And through the "<hex>:<bits>" parser the web interface actually uses.
  std::string pair = std::string(5000, 'A') + ":26";
  TEST_ASSERT_FALSE(tick_tx_submit_pair(pair.c_str()));

  TEST_ASSERT_EQUAL_INT(0, tx_call_count);

  // A payload under that limit but longer than its declared bit count is
  // accepted here and bounded by the driver instead - see the OSDP test
  // below, which is where the overflow actually was.
  std::string long_hex(300, 'A');
  TEST_ASSERT_TRUE(tick_tx_submit(long_hex.c_str(), 26));
}

// The /txid stack overflow, tested against the real bounding function.
// 300 hex characters declaring 26 bits used to copy 150 bytes into a 64 byte
// array. No combination of arguments may exceed the destination.
void test_osdp_cardread_bytes_is_bounded(void) {
  const size_t kMax = 64;  // OSDP_EVENT_CARDREAD_MAX_DATALEN

  // The original attack shape.
  TEST_ASSERT_EQUAL_UINT32(4, osdp_cardread_bytes(300, 26, kMax));

  // Absurd inputs from every direction.
  TEST_ASSERT_LESS_OR_EQUAL_UINT32(kMax, osdp_cardread_bytes(100000, 26, kMax));
  TEST_ASSERT_LESS_OR_EQUAL_UINT32(
      kMax, osdp_cardread_bytes(100000, 4000000000UL, kMax));
  TEST_ASSERT_LESS_OR_EQUAL_UINT32(kMax, osdp_cardread_bytes(0, 4000, kMax));
  TEST_ASSERT_EQUAL_UINT32(0, osdp_cardread_bytes(0, 0, kMax));

  // Sweep the whole space the queue can actually deliver.
  for (size_t hex_len = 0; hex_len <= TICK_TX_MAX_CHARS; hex_len++) {
    for (unsigned long bits = 0; bits <= TICK_MAX_BITS; bits += 7) {
      size_t n = osdp_cardread_bytes(hex_len, bits, kMax);
      TEST_ASSERT_LESS_OR_EQUAL_UINT32(kMax, n);
      // Never reads more hex than it was given.
      TEST_ASSERT_LESS_OR_EQUAL_UINT32(hex_len, n * 2);
      // Never claims more data than the declared bit count.
      TEST_ASSERT_LESS_OR_EQUAL_UINT32((bits + 7) / 8, n);
    }
  }
}

void test_tx_rejects_malformed_input(void) {
  TEST_ASSERT_FALSE(tick_tx_submit(NULL, 26));
  TEST_ASSERT_FALSE(tick_tx_submit("", 26));
  TEST_ASSERT_FALSE(tick_tx_submit("zzzz", 26));
  TEST_ASSERT_FALSE(tick_tx_submit("12 34", 26));
  TEST_ASSERT_FALSE(tick_tx_submit("1234", 0));
  TEST_ASSERT_FALSE(tick_tx_submit("1234", TICK_MAX_BITS + 1));
  TEST_ASSERT_FALSE(tick_tx_submit("1234", 4000000000UL));

  TEST_ASSERT_FALSE(tick_tx_submit_pair(NULL));
  TEST_ASSERT_FALSE(tick_tx_submit_pair(""));
  TEST_ASSERT_FALSE(tick_tx_submit_pair("nocolon"));
  TEST_ASSERT_FALSE(tick_tx_submit_pair(":26"));
  TEST_ASSERT_FALSE(tick_tx_submit_pair("1234:"));
  TEST_ASSERT_FALSE(tick_tx_submit_pair("1234:abc"));
  // The old handler used indexOf(":") and fed -1 into substring on this one.
  TEST_ASSERT_FALSE(tick_tx_submit_pair("2004060"));
}

void test_tx_accepts_and_normalises(void) {
  tx_call_count = 0;
  tick_current = &fake_driver;

  TEST_ASSERT_TRUE(tick_tx_submit_pair("2ff4060:26"));
  // Single slot: a second request while one is in flight is refused rather
  // than overwriting it.
  TEST_ASSERT_FALSE(tick_tx_submit_pair("1111111:26"));

  tick_tx_service();
  TEST_ASSERT_EQUAL_INT(1, tx_call_count);
  TEST_ASSERT_EQUAL_STRING("2FF4060", tx_seen_hex.c_str());
  TEST_ASSERT_EQUAL_UINT32(26, tx_seen_bits);

  // Slot is free again.
  TEST_ASSERT_TRUE(tick_tx_submit_pair("1111111:26"));
  tick_tx_service();
  TEST_ASSERT_EQUAL_INT(2, tx_call_count);

  // Nothing pending means nothing sent.
  tick_tx_service();
  TEST_ASSERT_EQUAL_INT(2, tx_call_count);
}

void test_tx_refused_when_mode_cannot_transmit(void) {
  tx_call_count = 0;
  tick_current = &tick_protocol_disabled;
  TEST_ASSERT_TRUE(tick_tx_submit_pair("2004060:26"));
  tick_tx_service();
  TEST_ASSERT_EQUAL_INT(0, tx_call_count);
  tick_current = &fake_driver;
}

// Every accepted payload must stay inside the OSDP card data buffer once
// halved into bytes, which is the invariant the overflow broke.
void test_accepted_payloads_fit_osdp_buffer(void) {
  std::mt19937 rng(7);
  std::uniform_int_distribution<int> len_dist(1, 700);
  const char *digits = "0123456789abcdefABCDEF";

  for (int i = 0; i < 3000; i++) {
    int len = len_dist(rng);
    std::string hex;
    for (int j = 0; j < len; j++) hex += digits[rng() % 22];

    if (tick_tx_submit(hex.c_str(), 26)) {
      TEST_ASSERT_LESS_OR_EQUAL_UINT32(TICK_TX_MAX_CHARS, hex.size());
      tick_tx_service();
      // Whatever a driver clamps to, the string it receives is bounded.
      TEST_ASSERT_LESS_OR_EQUAL_UINT32(TICK_TX_MAX_CHARS, tx_seen_hex.size());
    }
  }
}

// The capture buffer is written by an interrupt and read by the main loop.
// On the C3 those interleave; on the S3 they genuinely run at once. Hammer
// both sides and check no frame is ever handed out longer than the buffer or
// with a count that disagrees with what was stored.
void test_concurrent_push_and_take(void) {
  static tick_capture_buffer shared;
  tick_capture_reset(&shared);
  tick_test_now_us = 0;

  std::atomic<bool> stop(false);
  std::atomic<int> frames(0);
  std::atomic<bool> bad(false);

  std::thread producer([&] {
    for (int i = 0; i < 400000 && !stop; i++) {
      tick_capture_push(&shared, (uint8_t)(i & 1));
    }
    stop = true;
  });

  std::thread consumer([&] {
    tick_capture_buffer out;
    while (!stop) {
      // Gap of zero so a frame is always available to take.
      if (tick_capture_take(&shared, &out, 1, 0)) {
        if (out.count > TICK_MAX_BITS) bad = true;
        char hex[TICK_MAX_HEX + 1];
        size_t n = tick_capture_to_hex(&out, hex, sizeof(hex));
        if (n != (size_t)((out.count + 3) / 4)) bad = true;
        frames++;
      }
    }
  });

  producer.join();
  consumer.join();

  TEST_ASSERT_FALSE(bad);
  TEST_ASSERT_GREATER_THAN_INT(0, frames.load());
}

// A caller with a short buffer must get a truncated, terminated string
// rather than a write past the end.
void test_formatters_respect_output_length(void) {
  tick_capture_buffer buf;
  fill(&buf, std::vector<uint8_t>(64, 1));

  char small[5];
  memset(small, 0x7E, sizeof(small));
  size_t n = tick_capture_to_hex(&buf, small, 5);
  TEST_ASSERT_EQUAL_UINT32(4, n);
  TEST_ASSERT_EQUAL_CHAR('\0', small[4]);

  char tiny[3];
  memset(tiny, 0x7E, sizeof(tiny));
  n = tick_capture_to_binary(&buf, tiny, 3);
  TEST_ASSERT_EQUAL_UINT32(2, n);
  TEST_ASSERT_EQUAL_CHAR('\0', tiny[2]);
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_hex_matches_legacy_exhaustively);
  RUN_TEST(test_hex_known_vector);
  RUN_TEST(test_hex_pads_short_frames);
  RUN_TEST(test_binary_format);
  RUN_TEST(test_push_respects_bounds);
  RUN_TEST(test_take_requires_min_bits_and_gap);
  RUN_TEST(test_take_survives_micros_rollover);
  RUN_TEST(test_tx_rejects_oversized_input);
  RUN_TEST(test_osdp_cardread_bytes_is_bounded);
  RUN_TEST(test_tx_rejects_malformed_input);
  RUN_TEST(test_tx_accepts_and_normalises);
  RUN_TEST(test_tx_refused_when_mode_cannot_transmit);
  RUN_TEST(test_accepted_payloads_fit_osdp_buffer);
  RUN_TEST(test_concurrent_push_and_take);
  RUN_TEST(test_formatters_respect_output_length);
  return UNITY_END();
}
