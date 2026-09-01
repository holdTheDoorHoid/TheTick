// Minimal Arduino surface so the real firmware sources can be compiled and
// exercised on a development machine. This is a test fixture, not firmware.
#ifndef TICK_TEST_ARDUINO_H
#define TICK_TEST_ARDUINO_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <mutex>
#include <string>

#define IRAM_ATTR
#define PROGMEM
#define F(x) (x)

typedef uint8_t byte;

// Critical sections are backed by a real mutex here. On the device these
// disable interrupts; making them a genuine lock on the host means the
// threaded tests actually exercise the locking discipline rather than
// pretending it exists.
struct tick_test_mux {
  std::mutex m;
};
typedef tick_test_mux portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED {}
#define portENTER_CRITICAL(mux) ((mux)->m.lock())
#define portEXIT_CRITICAL(mux) ((mux)->m.unlock())
#define portENTER_CRITICAL_ISR(mux) ((mux)->m.lock())
#define portEXIT_CRITICAL_ISR(mux) ((mux)->m.unlock())

// Test-controlled clock.
extern uint32_t tick_test_now_us;
inline uint32_t micros(void) { return tick_test_now_us; }
inline uint32_t millis(void) { return tick_test_now_us / 1000; }

// Enough of Arduino String for the code under test.
class String {
 public:
  String() {}
  String(const char *s) : s_(s ? s : "") {}
  String(const std::string &s) : s_(s) {}
  String(int v) : s_(std::to_string(v)) {}
  String(unsigned int v) : s_(std::to_string(v)) {}
  String(long v) : s_(std::to_string(v)) {}
  String(unsigned long v) : s_(std::to_string(v)) {}

  const char *c_str() const { return s_.c_str(); }
  size_t length() const { return s_.size(); }
  char operator[](size_t i) const { return i < s_.size() ? s_[i] : 0; }

  String &operator+=(const String &o) {
    s_ += o.s_;
    return *this;
  }
  String &operator+=(const char *o) {
    s_ += o;
    return *this;
  }
  String &operator+=(char c) {
    s_ += c;
    return *this;
  }
  void reserve(unsigned int n) { s_.reserve(n); }
  bool operator==(const char *o) const { return s_ == o; }

  std::string s_;
};

inline String operator+(const String &a, const String &b) {
  String r(a);
  r += b;
  return r;
}
inline String operator+(const String &a, const char *b) {
  String r(a);
  r += b;
  return r;
}
inline String operator+(const char *a, const String &b) {
  String r(a);
  r += b;
  return r;
}

#endif
