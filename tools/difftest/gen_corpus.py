#!/usr/bin/env python3
"""Generate a shared corpus for the C-versus-Rust dissector comparison.

A rewrite is only trustworthy if it behaves the same on the inputs that
matter, and for a wire parser those are mostly the malformed ones. The corpus
is therefore weighted towards frames that are nearly valid: right start byte,
wrong length; valid header, truncated body; correct structure, corrupted
trailer.
"""
import random
import sys

SOM = 0x53
MARK = 0xFF


def crc16(buf):
    seed = 0x1D0F
    for b in buf:
        seed = ((seed >> 8) | (seed << 8)) & 0xFFFF
        seed ^= b
        seed ^= (seed & 0xFF) >> 4
        seed = (seed ^ (seed << 12)) & 0xFFFF
        seed = (seed ^ ((seed & 0xFF) << 5)) & 0xFFFF
    return seed


def checksum(buf):
    return ((~(sum(buf) & 0xFF)) + 1) & 0xFF


def build(rng, valid_trailer=True):
    addr = rng.randrange(0, 128) | (0x80 if rng.random() < 0.5 else 0)
    use_crc = rng.random() < 0.7
    scb = None
    if rng.random() < 0.5:
        kind = rng.choice([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                           rng.randrange(0, 256)])
        scb = (kind, bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 6))))

    p = [SOM, addr, 0, 0]
    control = rng.randrange(0, 4)
    if use_crc:
        control |= 0x04
    if scb:
        control |= 0x08
    p.append(control)
    if scb:
        p.append(2 + len(scb[1]))
        p.append(scb[0])
        p.extend(scb[1])
    p.append(rng.choice([0x60, 0x61, 0x62, 0x50, 0x46, 0x76, 0x75,
                         rng.randrange(0, 256)]))
    p.extend(rng.randrange(0, 256) for _ in range(rng.randrange(0, 24)))

    total = len(p) + (2 if use_crc else 1)
    p[2] = total & 0xFF
    p[3] = (total >> 8) & 0xFF

    if use_crc:
        c = crc16(bytes(p))
        if not valid_trailer:
            c ^= 0xFFFF
        p.append(c & 0xFF)
        p.append((c >> 8) & 0xFF)
    else:
        s = checksum(bytes(p))
        if not valid_trailer:
            s ^= 0xFF
        p.append(s)

    if rng.random() < 0.2:
        p = [MARK] + p
    return bytes(p)


def main():
    rng = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 1234)
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 60000
    out = []

    for i in range(count):
        r = rng.random()
        if r < 0.30:
            out.append(build(rng, valid_trailer=True))
        elif r < 0.45:
            out.append(build(rng, valid_trailer=False))
        elif r < 0.60:
            # Truncate a valid frame at an arbitrary point.
            f = build(rng)
            out.append(f[: rng.randrange(0, len(f) + 1)])
        elif r < 0.75:
            # Valid frame with one byte corrupted, which is where length and
            # security block handling gets interesting.
            f = bytearray(build(rng))
            if f:
                f[rng.randrange(0, len(f))] = rng.randrange(0, 256)
            out.append(bytes(f))
        elif r < 0.85:
            # Structured noise: right start byte, everything else random.
            n = rng.randrange(1, 40)
            b = bytearray(rng.randrange(0, 256) for _ in range(n))
            b[0] = SOM
            out.append(bytes(b))
        else:
            n = rng.randrange(0, 48)
            out.append(bytes(rng.randrange(0, 256) for _ in range(n)))

    for b in out:
        print(b.hex())


if __name__ == "__main__":
    main()
