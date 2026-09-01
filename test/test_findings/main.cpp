// Host-side tests for the evidence store.
//
// This is the part that becomes a client deliverable, so the bar is that it
// never produces a document that cannot be parsed - including when the
// buffer is too small, the store is full, or a captured value contains bytes
// that would otherwise break the encoding.

#include <unity.h>

#include <cstring>
#include <string>
#include <vector>

#include "../../src/tick_findings.cpp"

static tick_findings store;

void setUp(void) { tick_findings_init(&store); }
void tearDown(void) {}

// Extremely small JSON validity check: balanced braces and brackets, quotes
// paired. Enough to catch a truncated or half written object.
static bool looks_like_valid_json(const std::string &s) {
  int braces = 0, brackets = 0, quotes = 0;
  bool escaped = false;
  for (char c : s) {
    if (escaped) { escaped = false; continue; }
    if (c == '\\') { escaped = true; continue; }
    if (c == '"') quotes++;
    if (quotes % 2 == 1) continue;  // inside a string
    if (c == '{') braces++;
    if (c == '}') braces--;
    if (c == '[') brackets++;
    if (c == ']') brackets--;
    if (braces < 0 || brackets < 0) return false;
  }
  return braces == 0 && brackets == 0 && quotes % 2 == 0;
}

void test_empty_store_is_an_empty_array(void) {
  char buf[64];
  tick_findings_to_json(&store, buf, sizeof(buf));
  TEST_ASSERT_EQUAL_STRING("[]", buf);
  TEST_ASSERT_EQUAL_UINT32(0, tick_findings_count(&store));
}

void test_records_and_serialises(void) {
  tick_finding_record(&store, "weak_key", "04040404040404040404040404040404",
                      TICK_SEVERITY_CRITICAL, true, 1, 1000);
  TEST_ASSERT_EQUAL_UINT32(1, tick_findings_count(&store));
  TEST_ASSERT_EQUAL_INT(TICK_SEVERITY_CRITICAL, tick_findings_worst(&store));

  char buf[512];
  tick_findings_to_json(&store, buf, sizeof(buf));
  std::string s(buf);
  TEST_ASSERT_TRUE(looks_like_valid_json(s));
  TEST_ASSERT_TRUE(s.find("\"name\":\"weak_key\"") != std::string::npos);
  TEST_ASSERT_TRUE(s.find("\"severity\":\"critical\"") != std::string::npos);
  TEST_ASSERT_TRUE(s.find("04040404") != std::string::npos);
  TEST_ASSERT_TRUE(s.find("\"address\":1") != std::string::npos);
}

// A device on a bus for a week must not produce a thousand identical rows.
void test_repeat_findings_fold_together(void) {
  for (int i = 0; i < 500; i++) {
    tick_finding_record(&store, "cleartext_card_read", "", TICK_SEVERITY_HIGH,
                        true, 1, (uint32_t)(1000 + i));
  }
  TEST_ASSERT_EQUAL_UINT32(1, tick_findings_count(&store));
  TEST_ASSERT_EQUAL_UINT32(500, store.items[0].count);
  TEST_ASSERT_EQUAL_UINT32(1000, store.items[0].first_ms);
  TEST_ASSERT_EQUAL_UINT32(1499, store.items[0].last_ms);
}

// The same weakness on two peripherals is two findings, because a report
// naming only one of them is wrong.
void test_same_finding_on_two_peers_is_two_rows(void) {
  tick_finding_record(&store, "cleartext_session", "", TICK_SEVERITY_HIGH, true,
                      1, 10);
  tick_finding_record(&store, "cleartext_session", "", TICK_SEVERITY_HIGH, true,
                      2, 20);
  TEST_ASSERT_EQUAL_UINT32(2, tick_findings_count(&store));
}

// A later observation that carries the proof should fill in a row recorded
// before the proof was available.
void test_detail_is_filled_in_when_it_arrives(void) {
  tick_finding_record(&store, "weak_key", "", TICK_SEVERITY_CRITICAL, true, 1,
                      10);
  TEST_ASSERT_EQUAL_STRING("", store.items[0].detail);
  tick_finding_record(&store, "weak_key", "deadbeef", TICK_SEVERITY_CRITICAL,
                      true, 1, 20);
  TEST_ASSERT_EQUAL_STRING("deadbeef", store.items[0].detail);
}

void test_severity_escalates_but_never_drops(void) {
  tick_finding_record(&store, "x", "", TICK_SEVERITY_LOW, false, 0, 1);
  tick_finding_record(&store, "x", "", TICK_SEVERITY_CRITICAL, false, 0, 2);
  TEST_ASSERT_EQUAL_INT(TICK_SEVERITY_CRITICAL, store.items[0].severity);
  tick_finding_record(&store, "x", "", TICK_SEVERITY_INFO, false, 0, 3);
  TEST_ASSERT_EQUAL_INT(TICK_SEVERITY_CRITICAL, store.items[0].severity);
}

// Values read off a wire must not be able to break the report they land in.
void test_hostile_detail_cannot_break_the_json(void) {
  tick_finding_record(&store, "injected", "\",\"severity\":\"info\",\"x\":\"",
                      TICK_SEVERITY_HIGH, false, 0, 1);
  tick_finding_record(&store, "newline", "line1\nline2\r\n\t",
                      TICK_SEVERITY_HIGH, false, 0, 2);
  tick_finding_record(&store, "backslash", "a\\\\b\\\"c", TICK_SEVERITY_HIGH,
                      false, 0, 3);
  tick_finding_record(&store, "highbytes", "\xff\xfe\x01\x02ok",
                     TICK_SEVERITY_HIGH, false, 0, 4);

  char buf[1024];
  tick_findings_to_json(&store, buf, sizeof(buf));
  std::string s(buf);
  TEST_ASSERT_TRUE_MESSAGE(looks_like_valid_json(s), s.c_str());
  // The injection attempt must not have produced a second severity key in
  // that object.
  TEST_ASSERT_TRUE(s.find("\"severity\":\"info\"") == std::string::npos);
}

// A name longer than the field must not run off the end.
void test_oversized_inputs_are_truncated_safely(void) {
  std::string long_name(500, 'A');
  std::string long_detail(500, 'B');
  tick_finding_record(&store, long_name.c_str(), long_detail.c_str(),
                      TICK_SEVERITY_HIGH, false, 0, 1);
  TEST_ASSERT_EQUAL_UINT32(1, tick_findings_count(&store));
  TEST_ASSERT_TRUE(strlen(store.items[0].name) < TICK_FINDING_NAME_LEN);
  TEST_ASSERT_TRUE(strlen(store.items[0].detail) < TICK_FINDING_DETAIL_LEN);

  char buf[512];
  tick_findings_to_json(&store, buf, sizeof(buf));
  TEST_ASSERT_TRUE(looks_like_valid_json(std::string(buf)));
}

void test_store_full_is_counted_not_silent(void) {
  for (int i = 0; i < TICK_MAX_FINDINGS + 10; i++) {
    char name[32];
    snprintf(name, sizeof(name), "finding_%d", i);
    tick_finding_record(&store, name, "", TICK_SEVERITY_LOW, false, 0, 1);
  }
  TEST_ASSERT_EQUAL_UINT32(TICK_MAX_FINDINGS, tick_findings_count(&store));
  TEST_ASSERT_EQUAL_UINT32(10, store.dropped);
}

// Every buffer size from tiny to ample must yield parseable JSON.
void test_every_buffer_size_yields_valid_json(void) {
  for (int i = 0; i < TICK_MAX_FINDINGS; i++) {
    char name[32];
    snprintf(name, sizeof(name), "finding_%d", i);
    tick_finding_record(&store, name, "0011223344556677", TICK_SEVERITY_HIGH,
                        true, (uint8_t)i, (uint32_t)(i * 100));
  }

  // Below three characters there is no valid document to emit, which is
  // covered separately.
  for (size_t n = 3; n <= 2048; n++) {
    std::vector<char> buf(n);
    size_t written = tick_findings_to_json(&store, buf.data(), n);
    TEST_ASSERT_TRUE(written < n);
    std::string s(buf.data());
    TEST_ASSERT_TRUE_MESSAGE(looks_like_valid_json(s),
                             ("invalid at buffer size " + std::to_string(n) +
                              ": " + s).c_str());
  }
}

// A buffer too small for even "[]" must yield an empty string, never a lone
// opening bracket.
void test_buffer_too_small_for_any_document(void) {
  tick_finding_record(&store, "x", "y", TICK_SEVERITY_HIGH, false, 0, 1);
  for (size_t n = 1; n <= 2; n++) {
    char buf[4] = {'Z', 'Z', 'Z', 'Z'};
    size_t written = tick_findings_to_json(&store, buf, n);
    TEST_ASSERT_EQUAL_UINT32(0, written);
    TEST_ASSERT_EQUAL_CHAR('\0', buf[0]);
  }
}

void test_null_arguments_are_safe(void) {
  char buf[32];
  TEST_ASSERT_EQUAL_UINT32(0, tick_findings_count(NULL));
  tick_findings_to_json(NULL, buf, sizeof(buf));
  TEST_ASSERT_EQUAL_STRING("[]", buf);
  tick_finding_record(NULL, "x", "y", TICK_SEVERITY_LOW, false, 0, 1);
  tick_finding_record(&store, NULL, "y", TICK_SEVERITY_LOW, false, 0, 1);
  tick_finding_record(&store, "ok", NULL, TICK_SEVERITY_LOW, false, 0, 1);
  TEST_ASSERT_EQUAL_UINT32(1, tick_findings_count(&store));
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_empty_store_is_an_empty_array);
  RUN_TEST(test_records_and_serialises);
  RUN_TEST(test_repeat_findings_fold_together);
  RUN_TEST(test_same_finding_on_two_peers_is_two_rows);
  RUN_TEST(test_detail_is_filled_in_when_it_arrives);
  RUN_TEST(test_severity_escalates_but_never_drops);
  RUN_TEST(test_hostile_detail_cannot_break_the_json);
  RUN_TEST(test_oversized_inputs_are_truncated_safely);
  RUN_TEST(test_store_full_is_counted_not_silent);
  RUN_TEST(test_every_buffer_size_yields_valid_json);
  RUN_TEST(test_buffer_too_small_for_any_document);
  RUN_TEST(test_null_arguments_are_safe);
  return UNITY_END();
}
