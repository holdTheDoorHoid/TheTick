// AES-128 correctness, pinned to the FIPS-197 known-answer vectors.
//
// This implementation exists only to run a known-plaintext oracle against
// captured OSDP handshakes. It protects nothing. It still has to be exactly
// right, or the weak-key check silently reports nothing.

#include <unity.h>

#include <cstdio>
#include <cstring>

#include "../../src/tick_aes128.cpp"

static void check(const char *key_hex, const char *pt_hex, const char *ct_hex) {
  uint8_t key[16], pt[16], want[16], got[16];
  auto parse = [](const char *hex, uint8_t *out) {
    for (int i = 0; i < 16; i++) {
      unsigned v = 0;
      sscanf(hex + i * 2, "%2x", &v);
      out[i] = (uint8_t)v;
    }
  };
  parse(key_hex, key);
  parse(pt_hex, pt);
  parse(ct_hex, want);

  aes128_encrypt(key, pt, got);
  TEST_ASSERT_EQUAL_HEX8_ARRAY(want, got, 16);
}

// FIPS-197 Appendix C.1.
void test_fips197_appendix_c1(void) {
  check("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a");
}

// FIPS-197 Appendix B, the worked example.
void test_fips197_appendix_b(void) {
  check("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734",
        "3925841d02dc09fbdc118597196a0b32");
}

// NIST SP 800-38A ECB-AES128 vectors.
void test_sp800_38a_vectors(void) {
  const char *key = "2b7e151628aed2a6abf7158809cf4f3c";
  check(key, "6bc1bee22e409f96e93d7e117393172a",
        "3ad77bb40d7a3660a89ecaf32466ef97");
  check(key, "ae2d8a571e03ac9c9eb76fac45af8e51",
        "f5d3d58503b9699de785895a96fdbaaf");
  check(key, "30c81c46a35ce411e5fbc1191a0a52ef",
        "43b1cd7f598ece23881b00e3ed030688");
  check(key, "f69f2445df4f9b17ad2b417be66c3710",
        "7b0c785e27e8ad3f8223207104725dd4");
}

// The all-zero key and block, which is where an implementation that skips a
// step often still looks plausible.
void test_zero_key_vector(void) {
  check("00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "66e94bd4ef8a2c3b884cfa59ca342b2e");
}

// In-place encryption must not corrupt the result.
void test_in_place_encryption(void) {
  uint8_t key[16], buf[16], want[16];
  for (int i = 0; i < 16; i++) {
    key[i] = (uint8_t)i;
    buf[i] = (uint8_t)(0x10 + i);
  }
  aes128_encrypt(key, buf, want);
  aes128_encrypt(key, buf, buf);
  TEST_ASSERT_EQUAL_HEX8_ARRAY(want, buf, 16);
}

// Expanding once and reusing the schedule must match the one-shot call, since
// the weak-key search does exactly that 768 times.
void test_expanded_key_reuse(void) {
  uint8_t key[16];
  for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 7);

  uint8_t rk[AES128_ROUND_KEYS];
  aes128_expand_key(key, rk);

  for (int trial = 0; trial < 64; trial++) {
    uint8_t pt[16], a[16], b[16];
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(trial * 16 + i);
    aes128_encrypt_block(rk, pt, a);
    aes128_encrypt(key, pt, b);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(a, b, 16);
  }
}

void setUp(void) {}
void tearDown(void) {}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_fips197_appendix_c1);
  RUN_TEST(test_fips197_appendix_b);
  RUN_TEST(test_sp800_38a_vectors);
  RUN_TEST(test_zero_key_vector);
  RUN_TEST(test_in_place_encryption);
  RUN_TEST(test_expanded_key_reuse);
  return UNITY_END();
}
