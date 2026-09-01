// Host-side tests for the per-chip pin rules.
//
// These matter because pin numbers come out of a text file the operator
// edits, and the legal set differs sharply between the C3, S3 and C5. A
// config written for one chip and flashed onto another is the ordinary way
// this goes wrong, and the failure mode - driving a pin wired to the flash
// chip - is one you cannot recover from a device sealed inside a reader.
//
// Expressing the rules as pure functions of (chip, pin) is what lets a single
// host build check all three chips, including the ones this firmware image
// was not compiled for.

#include <unity.h>

#include "Arduino.h"

uint32_t tick_test_now_us = 0;

void append_log(String facility, String text) {
  (void)facility;
  (void)text;
}
void output_debug_string(String s) { (void)s; }

// Compile the board layer for the C3, so tick_chip_current() has a definite
// answer while the pure helpers are exercised for every chip.
#define CONFIG_IDF_TARGET_ESP32C3 1
#define TICK_BOARD_C3_SUPERMINI_REV02 1
#define SOC_GPIO_PIN_COUNT 22
#define GPIO_IS_VALID_GPIO(n) ((n) >= 0 && (n) < SOC_GPIO_PIN_COUNT)
#define GPIO_IS_VALID_OUTPUT_GPIO(n) GPIO_IS_VALID_GPIO(n)

#include "../../src/tick_board.cpp"

// The pins each chip commits to flash, PSRAM or USB. Getting one of these
// wrong is the difference between a working port and a brick.
void test_c3_reserved_pins(void) {
  for (int p = 11; p <= 17; p++) {
    TEST_ASSERT_TRUE_MESSAGE(tick_pin_reserved_on(TICK_CHIP_ESP32C3, p),
                             "C3 flash pins must be reserved");
  }
  TEST_ASSERT_TRUE(tick_pin_reserved_on(TICK_CHIP_ESP32C3, 18));
  TEST_ASSERT_TRUE(tick_pin_reserved_on(TICK_CHIP_ESP32C3, 19));

  // The pins the shipping board actually uses must not be reserved.
  int in_use[] = {0, 1, 4, 5, 7, 9, 10, 20, 21};
  for (int p : in_use) {
    TEST_ASSERT_FALSE_MESSAGE(tick_pin_reserved_on(TICK_CHIP_ESP32C3, p),
                              "a pin the board uses was marked reserved");
  }
}

void test_s3_reserved_pins(void) {
  for (int p = 26; p <= 37; p++) {
    TEST_ASSERT_TRUE_MESSAGE(tick_pin_reserved_on(TICK_CHIP_ESP32S3, p),
                             "S3 flash/PSRAM pins must be reserved");
  }
  TEST_ASSERT_TRUE(tick_pin_reserved_on(TICK_CHIP_ESP32S3, 19));  // USB D-
  TEST_ASSERT_TRUE(tick_pin_reserved_on(TICK_CHIP_ESP32S3, 20));  // USB D+

  TEST_ASSERT_FALSE(tick_pin_reserved_on(TICK_CHIP_ESP32S3, 4));
  TEST_ASSERT_FALSE(tick_pin_reserved_on(TICK_CHIP_ESP32S3, 18));
  TEST_ASSERT_FALSE(tick_pin_reserved_on(TICK_CHIP_ESP32S3, 21));
  TEST_ASSERT_FALSE(tick_pin_reserved_on(TICK_CHIP_ESP32S3, 48));
}

void test_c5_reserved_pins(void) {
  for (int p = 24; p <= 28; p++) {
    TEST_ASSERT_TRUE(tick_pin_reserved_on(TICK_CHIP_ESP32C5, p));
  }
  TEST_ASSERT_TRUE(tick_pin_reserved_on(TICK_CHIP_ESP32C5, 13));
  TEST_ASSERT_TRUE(tick_pin_reserved_on(TICK_CHIP_ESP32C5, 14));
  TEST_ASSERT_FALSE(tick_pin_reserved_on(TICK_CHIP_ESP32C5, 4));
}

// Every pin the S3 board table hands out must be usable on the S3. This is
// the check that would have caught a copy-paste from the C3 entry.
void test_s3_board_pins_are_legal_on_s3(void) {
  struct {
    const char *what;
    int pin;
  } pins[] = {
      {"d0", 4},   {"d1", 5},   {"aux", 6},  {"reset", 0}, {"vsense", 7},
      {"de", 15},  {"re", 16},  {"rx", 17},  {"tx", 18},
  };

  for (auto &p : pins) {
    TEST_ASSERT_FALSE_MESSAGE(tick_pin_reserved_on(TICK_CHIP_ESP32S3, p.pin),
                              p.what);
    TEST_ASSERT_TRUE_MESSAGE(p.pin >= 0 &&
                                 p.pin < tick_chip_pin_count(TICK_CHIP_ESP32S3),
                             p.what);
  }

  // The voltage divider has to be on ADC1, or it reads nonsense whenever the
  // radio is on - which is always.
  TEST_ASSERT_TRUE(tick_pin_is_adc1_on(TICK_CHIP_ESP32S3, 7));
}

void test_c3_board_pins_are_legal_on_c3(void) {
  TEST_ASSERT_FALSE(tick_pin_reserved_on(TICK_CHIP_ESP32C3, TICK_BOARD.pin_d0));
  TEST_ASSERT_FALSE(tick_pin_reserved_on(TICK_CHIP_ESP32C3, TICK_BOARD.pin_d1));
  TEST_ASSERT_FALSE(
      tick_pin_reserved_on(TICK_CHIP_ESP32C3, TICK_BOARD.pin_reset));
  TEST_ASSERT_TRUE(tick_pin_is_adc1_on(TICK_CHIP_ESP32C3, TICK_BOARD.pin_vsense));
}

// A C3 config moved onto an S3 board, and the reverse. The point is not that
// these particular numbers are wrong, but that the rules disagree between
// chips, which is why the check exists at all.
void test_configs_do_not_travel_between_chips(void) {
  // GPIO 20 is the C3's OSDP receive pin and the S3's USB D+.
  TEST_ASSERT_FALSE(tick_pin_reserved_on(TICK_CHIP_ESP32C3, 20));
  TEST_ASSERT_TRUE(tick_pin_reserved_on(TICK_CHIP_ESP32S3, 20));

  // GPIO 16 is usable on the S3 and is SPI flash on the C3.
  TEST_ASSERT_FALSE(tick_pin_reserved_on(TICK_CHIP_ESP32S3, 16));
  TEST_ASSERT_TRUE(tick_pin_reserved_on(TICK_CHIP_ESP32C3, 16));
}

// The sentinel that used to be -1 stored in a uint8_t, arriving as 255.
void test_absent_pin_sentinel(void) {
  TEST_ASSERT_EQUAL_INT(-1, TICK_PIN_NONE);
  TEST_ASSERT_FALSE(tick_pin_is_valid(TICK_PIN_NONE));
  TEST_ASSERT_FALSE(tick_pin_is_valid(255));
  TEST_ASSERT_FALSE(tick_pin_is_valid_output(255));

  // A board with no terminator keeps the sentinel rather than being handed a
  // fallback pin to drive.
  TEST_ASSERT_EQUAL_INT(TICK_PIN_NONE,
                        tick_pin_checked("term", TICK_PIN_NONE, 7, true));
}

void test_pin_checked_falls_back(void) {
  // Legal pin is kept.
  TEST_ASSERT_EQUAL_INT(5, tick_pin_checked("aux", 5, 9, false));
  // Flash pin is rejected in favour of the board default.
  TEST_ASSERT_EQUAL_INT(9, tick_pin_checked("aux", 13, 9, false));
  // Out of range in both directions.
  TEST_ASSERT_EQUAL_INT(9, tick_pin_checked("aux", 99, 9, false));
  TEST_ASSERT_EQUAL_INT(9, tick_pin_checked("aux", -7, 9, false));
}

// Nothing may report as valid outside the chip's own pin range.
void test_validity_never_exceeds_pin_count(void) {
  for (int p = -1000; p < 1000; p++) {
    if (tick_pin_is_valid(p)) {
      TEST_ASSERT_TRUE(p >= 0 && p < SOC_GPIO_PIN_COUNT);
      TEST_ASSERT_FALSE(tick_pin_reserved_on(TICK_CHIP_ESP32C3, p));
    }
  }
}

void setUp(void) {}
void tearDown(void) {}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_c3_reserved_pins);
  RUN_TEST(test_s3_reserved_pins);
  RUN_TEST(test_c5_reserved_pins);
  RUN_TEST(test_s3_board_pins_are_legal_on_s3);
  RUN_TEST(test_c3_board_pins_are_legal_on_c3);
  RUN_TEST(test_configs_do_not_travel_between_chips);
  RUN_TEST(test_absent_pin_sentinel);
  RUN_TEST(test_pin_checked_falls_back);
  RUN_TEST(test_validity_never_exceeds_pin_count);
  return UNITY_END();
}
