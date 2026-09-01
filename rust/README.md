# The Tick in Rust

An in-progress port of the firmware to Rust, taking the code that parses
untrusted input first.

## Why, precisely

"Rewrite it in Rust" is not by itself a security argument, so here is the
specific one.

The bugs found in the C firmware during review were, in order of severity:
an unbounded heap allocation inside an interrupt handler; an unchecked copy
into a 64-byte buffer driven by an attacker-supplied length; shared state
between an interrupt and the main loop with no synchronisation; and a parser
walking a wire it does not control. Every one of those is a class the Rust
compiler either eliminates or forces you to handle explicitly.

What this does **not** fix, and it would be dishonest to imply otherwise:

- The Wi-Fi, TCP/IP and Bluetooth stacks stay C. On `esp-idf-svc` they are
  ESP-IDF; on `esp-hal` the radio is still a vendor binary blob. Nothing in
  this port changes that.
- Logic errors survive translation. The OSDP control-panel mode crashed
  because it passed a null command every loop; a faithful port would crash
  identically. Memory safety is not correctness.
- `libosdp` is C. Anything that keeps using it keeps its bugs.

The honest claim is narrower and still worth having: **the code that touches
hostile bytes becomes memory-safe, and the concurrency bugs that the
single-core C3 was hiding become compile errors rather than field failures on
the dual-core S3.**

## Toolchain reality, and a tradeoff worth knowing about

This is the one place where Rust is *worse* than the current C++ setup for
this project, and it should be a deliberate choice rather than a surprise.

| Chip | Architecture | Toolchain |
|------|--------------|-----------|
| ESP32-C3 | RISC-V | upstream Rust |
| ESP32-C5 | RISC-V | upstream Rust |
| ESP32-C6 | RISC-V | upstream Rust |
| ESP32-S3 | Xtensa | **esp-rs Rust fork, via `espup`** |

Xtensa is not supported by upstream LLVM, so the S3 needs Espressif's compiler
fork. In the C++ build the S3 was a different backend of the same toolchain
and cost nothing but a new environment. Here it costs a second compiler.

The RISC-V parts are unaffected, and the crates in this directory are
architecture-neutral - they build and are tested on the development machine.

## Layout

```
rust/
  tick-osdp/     OSDP frame dissection and code tables
```

Crates here are `no_std` and inherit workspace lints that **forbid `unsafe`**
and deny indexing, unwrapping, panicking and arithmetic that could overflow.
Those denials are what turn "we reviewed it carefully" into "it does not
compile otherwise". They are relaxed in tests and dev harnesses, where a panic
is how an assertion reports failure.

## Verifying the port

A rewrite is only trustworthy if it behaves the same as what it replaces, so
the dissector is checked against the C implementation directly rather than
only against its own tests.

```sh
cd rust && cargo test                        # unit tests, incl. 200k fuzz iterations
cd rust && cargo clippy --all-targets -- -D warnings
cd rust && cargo +nightly miri test --test dissect \
    -- --skip fuzzing_never_panics --skip the_stream_scanner_always_terminates

# Differential: the same corpus through both implementations, compared exactly
g++ -std=gnu++17 -O2 -Iinclude -o /tmp/c_harness tools/difftest/c_harness.cpp
cargo build --release --manifest-path rust/Cargo.toml --example difftest_harness
python3 tools/difftest/gen_corpus.py 1234 60000 > /tmp/corpus.txt
/tmp/c_harness < /tmp/corpus.txt > /tmp/out_c.txt
./rust/target/release/examples/difftest_harness < /tmp/corpus.txt > /tmp/out_rust.txt
diff /tmp/out_c.txt /tmp/out_rust.txt
```

The corpus is weighted towards nearly-valid frames, because that is where a
parser goes wrong: right start byte and wrong length, valid header and
truncated body, correct structure and a corrupted trailer.

Current state: **300,000 inputs across six seeds, byte-for-byte identical
output.** Clippy clean under the strict lints. Miri reports no undefined
behaviour.

## Order of work

Deliberately sequenced by how much risk each step removes, not by how much of
the codebase it covers.

1. **OSDP dissector** — done. The hostile-input parser, the highest-risk code
   in the firmware.
2. **Threat monitor** — the detection state machine on top of the dissector.
   Pure logic, ports directly, tests come with it.
3. **Crypto** — replace the hand-written AES with RustCrypto `aes`, and use
   `subtle` for the constant-time comparison the cryptogram check needs.
   `zeroize` for key material. This is a straight security upgrade: the
   current AES is correct against the FIPS vectors but is still hand-written
   cipher code, and the key comparison is not constant time.
4. **Capture path** — the bit buffer and transmit queue. The C version's
   interrupt-safety is enforced by comment; here it is a type.
5. **Findings and report** — the evidence store.
6. **Firmware shell** — the part that actually needs a microcontroller:
   `esp-idf-svc` for Wi-Fi, HTTP and storage, since `esp-hal` does not yet
   cover the HTTP server and BLE this device needs.

Steps 1 to 5 are testable on a development machine with no hardware. Step 6 is
not, which is why it is last.

## Migration, not a rewrite in one jump

The C++ firmware keeps working throughout. These crates are `no_std` with a C
ABI available, so a compiled staticlib can be linked into the existing
firmware and the C implementation deleted module by module, with the
differential harness proving equivalence at each step. A big-bang cutover
would mean a long period with neither version trustworthy.
