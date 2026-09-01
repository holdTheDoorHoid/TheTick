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

#ifndef TICK_AES128_H
#define TICK_AES128_H

#include <stdint.h>

// AES-128 single block encryption.
//
// This exists to run a known-plaintext oracle against captured OSDP secure
// channel handshakes: derive a session key from a candidate SCBK, recompute
// the cryptogram the peripheral sent, and see whether it matches. It is
// analysis code, not protection - nothing here guards data at rest or in
// flight, and none of it touches a key the device is trying to keep.
//
// Encryption only, one block, no modes: that is the entire requirement, and a
// smaller surface is easier to get right. Correctness is pinned by the
// FIPS-197 known-answer vectors in the test suite; the S-box was generated
// from its algebraic definition rather than transcribed.

#define AES128_BLOCK_SIZE 16
#define AES128_KEY_SIZE 16
#define AES128_ROUND_KEYS 176

// Expand a 128 bit key into the 11 round keys.
void aes128_expand_key(const uint8_t key[AES128_KEY_SIZE],
                       uint8_t round_keys[AES128_ROUND_KEYS]);

// Encrypt one block. `in` and `out` may be the same buffer.
void aes128_encrypt_block(const uint8_t round_keys[AES128_ROUND_KEYS],
                          const uint8_t in[AES128_BLOCK_SIZE],
                          uint8_t out[AES128_BLOCK_SIZE]);

// Convenience: expand and encrypt in one call.
void aes128_encrypt(const uint8_t key[AES128_KEY_SIZE],
                    const uint8_t in[AES128_BLOCK_SIZE],
                    uint8_t out[AES128_BLOCK_SIZE]);

#endif
