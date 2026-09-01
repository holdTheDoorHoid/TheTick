//! Tests for the OSDP frame dissector.
//!
//! The C version of this parser was fuzzed under AddressSanitizer because an
//! out-of-bounds read was possible in principle. Here that class is gone by
//! construction, so the fuzzing checks a different property: that no input
//! makes the parser panic. A panic on a microcontroller is a reboot, and a
//! reboot in the middle of an engagement is a lost capture.

// The workspace denies indexing, unwrapping and panicking because those are
// how firmware crashes on a wire it does not control. None of that applies to
// a test: a test that panics is a test that failed, which is the point.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_arguments
)]

use tick_osdp::{
    checksum, crc16, dissect, dissect_stream, Command, DissectError, Reply, SecurityBlockType,
    PKT_MARK, PKT_SOM,
};

/// Build a frame independently of the parser, from the specification.
fn build(
    address: u8,
    is_reply: bool,
    sequence: u8,
    use_crc: bool,
    scb: Option<(u8, &[u8])>,
    id: u8,
    payload: &[u8],
    with_mark: bool,
) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(PKT_SOM);
    p.push(address | if is_reply { 0x80 } else { 0 });
    p.push(0);
    p.push(0);

    let mut control = sequence & 0x03;
    if use_crc {
        control |= 0x04;
    }
    if scb.is_some() {
        control |= 0x08;
    }
    p.push(control);

    if let Some((kind, data)) = scb {
        p.push((2 + data.len()) as u8);
        p.push(kind);
        p.extend_from_slice(data);
    }

    p.push(id);
    p.extend_from_slice(payload);

    let total = p.len() + if use_crc { 2 } else { 1 };
    p[2] = (total & 0xFF) as u8;
    p[3] = ((total >> 8) & 0xFF) as u8;

    if use_crc {
        let c = crc16(&p);
        p.push((c & 0xFF) as u8);
        p.push((c >> 8) as u8);
    } else {
        p.push(checksum(&p));
    }

    if with_mark {
        let mut out = vec![PKT_MARK];
        out.extend_from_slice(&p);
        out
    } else {
        p
    }
}

/// OSDP uses CRC-16/AUG-CCITT. Its published check value is asserted here so
/// that a transcription error cannot hide behind a round trip through our own
/// encoder.
#[test]
fn crc_matches_published_check_value() {
    assert_eq!(crc16(b"123456789"), 0xE5CC);
}

#[test]
fn checksum_is_twos_complement() {
    let buf = [0x53u8, 0x00, 0x08, 0x00, 0x00, 0x60];
    let sum = buf.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    assert_eq!(checksum(&buf), (!sum).wrapping_add(1));
}

#[test]
fn parses_a_poll() {
    let bytes = build(0x65, false, 1, true, None, 0x60, &[], false);
    let (frame, consumed) = dissect(&bytes).expect("should parse");

    assert_eq!(frame.address, 0x65);
    assert!(!frame.is_reply);
    assert_eq!(frame.sequence, 1);
    assert!(frame.uses_crc);
    assert!(frame.security_block.is_none());
    assert_eq!(frame.command(), Some(Command::Poll));
    assert_eq!(frame.reply(), None);
    assert!(frame.payload.is_empty());
    assert!(frame.trailer_valid);
    assert_eq!(consumed, bytes.len());
    assert_eq!(frame.name(), "POLL");
}

#[test]
fn parses_a_reply_with_payload() {
    let card = [0x00u8, 0x01, 0x1A, 0x00, 0xAB, 0xCD];
    let bytes = build(0x7F, true, 2, true, None, 0x50, &card, false);
    let (frame, _) = dissect(&bytes).expect("should parse");

    assert!(frame.is_reply);
    assert_eq!(frame.address, 0x7F);
    assert_eq!(frame.reply(), Some(Reply::RawCardData));
    assert_eq!(frame.command(), None);
    assert_eq!(frame.payload, &card);
    assert!(frame.reply().expect("reply").carries_credential());
}

#[test]
fn parses_checksum_frames_and_mark_bytes() {
    let bytes = build(0x01, false, 0, false, None, 0x61, &[0x00], false);
    let (frame, _) = dissect(&bytes).expect("should parse");
    assert!(!frame.uses_crc);
    assert!(frame.trailer_valid);

    let marked = build(0x02, false, 0, true, None, 0x60, &[], true);
    let (frame, consumed) = dissect(&marked).expect("should parse");
    assert!(frame.has_mark);
    assert_eq!(consumed, marked.len());
}

/// Only two of the eight block types actually encrypt. Getting this wrong
/// would mean either missing an exposed credential or claiming one was
/// exposed when it was not.
#[test]
fn security_blocks_are_classified() {
    let cases = [
        (0x11u8, false, true),
        (0x12, false, true),
        (0x13, false, true),
        (0x14, false, true),
        (0x15, false, false),
        (0x16, false, false),
        (0x17, true, false),
        (0x18, true, false),
    ];

    for (kind, encrypted, handshake) in cases {
        let bytes = build(0x01, false, 1, true, Some((kind, &[0x01, 0x00])), 0x60, &[], false);
        let (frame, _) = dissect(&bytes).expect("should parse");
        let sb = frame.security_block.expect("security block present");

        assert_eq!(sb.kind, SecurityBlockType::from(kind));
        assert_eq!(sb.is_encrypted(), encrypted, "encryption for {kind:#04x}");
        assert_eq!(sb.is_handshake(), handshake, "handshake for {kind:#04x}");
        assert_eq!(frame.payload_encrypted(), encrypted);
        assert_eq!(sb.data, &[0x01, 0x00]);
    }
}

/// The handshake announces whether the specification's default key is in use,
/// which is detectable with no cryptography at all.
#[test]
fn default_key_is_visible_in_the_handshake() {
    let real = build(0x01, false, 1, true, Some((0x11, &[0x01])), 0x76, &[0u8; 8], false);
    let (frame, _) = dissect(&real).expect("should parse");
    assert!(!frame.security_block.expect("sb").uses_default_key());

    let scbkd = build(0x01, false, 1, true, Some((0x11, &[0x00])), 0x76, &[0u8; 8], false);
    let (frame, _) = dissect(&scbkd).expect("should parse");
    assert!(frame.security_block.expect("sb").uses_default_key());

    // A data block is not a handshake, whatever its first byte happens to be.
    let data = build(0x01, false, 1, true, Some((0x17, &[0x00])), 0x60, &[], false);
    let (frame, _) = dissect(&data).expect("should parse");
    assert!(!frame.security_block.expect("sb").uses_default_key());
}

#[test]
fn a_bad_trailer_is_reported_not_hidden() {
    let mut bytes = build(0x01, false, 0, true, None, 0x60, &[], false);
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;

    let (frame, _) = dissect(&bytes).expect("still parses structurally");
    assert!(!frame.trailer_valid);
}

#[test]
fn impossible_lengths_are_rejected() {
    // Shorter than a header can be. The C version needed care here to avoid
    // an unsigned subtraction wrapping into an enormous payload slice.
    let tiny = [0x53u8, 0x01, 0x02, 0x00, 0x04, 0x60, 0x00, 0x00];
    assert_eq!(dissect(&tiny), Err(DissectError::BadLength));

    let zero = [0x53u8, 0x01, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00];
    assert_eq!(dissect(&zero), Err(DissectError::BadLength));

    let huge = [0x53u8, 0x01, 0xFF, 0xFF, 0x04, 0x60, 0x00, 0x00];
    assert_eq!(dissect(&huge), Err(DissectError::BadLength));
}

#[test]
fn security_blocks_running_past_the_frame_are_rejected() {
    let mut bytes = build(0x01, false, 1, true, Some((0x17, &[0, 0])), 0x60, &[], false);
    bytes[5] = 0xFF;
    assert_eq!(dissect(&bytes), Err(DissectError::BadSecurityBlock));

    bytes[5] = 0x01; // too short to hold its own header
    assert_eq!(dissect(&bytes), Err(DissectError::BadSecurityBlock));
}

#[test]
fn truncated_frames_ask_for_more() {
    let bytes = build(0x01, false, 0, true, None, 0x46, &[1, 2, 3, 4, 5, 6], false);
    for n in 1..bytes.len() {
        assert_eq!(
            dissect(&bytes[..n]),
            Err(DissectError::NeedMore),
            "a truncated frame must not parse at {n} bytes"
        );
    }
    assert!(dissect(&bytes).is_ok());
}

#[test]
fn the_stream_scanner_resynchronises() {
    let frame = build(0x09, true, 3, true, None, 0x40, &[], false);
    let mut stream = vec![0x00, 0xAA, 0x53, 0x12, 0xFF, 0x99];
    let noise = stream.len();
    stream.extend_from_slice(&frame);

    let located = dissect_stream(&stream).expect("should find the frame");
    assert_eq!(located.offset, noise);
    assert_eq!(located.consumed, frame.len());
    assert_eq!(located.frame.reply(), Some(Reply::Ack));
}

#[test]
fn pure_noise_yields_no_frame() {
    let noise = [0x00u8, 0x11, 0x22, 0x33, 0x44];
    assert!(dissect_stream(&noise).is_err());
}

/// Every single bit of a valid frame flipped in turn. Nothing may be reported
/// as good unless its trailer genuinely still verifies.
#[test]
fn single_bit_corruption_never_yields_a_false_positive() {
    let good = build(0x11, true, 1, true, Some((0x16, &[0, 0])), 0x50, &[1, 2, 3, 4], false);

    for i in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[i] ^= 1 << bit;
            if let Ok((frame, consumed)) = dissect(&bad) {
                assert!(consumed <= bad.len());
                if frame.trailer_valid {
                    // Legitimate only if the trailer really does verify.
                    let end = usize::from(frame.length) - if frame.uses_crc { 2 } else { 1 };
                    let body_start = usize::from(frame.has_mark);
                    let body = &bad[body_start..body_start + end];
                    if frame.uses_crc {
                        let lo = bad[body_start + end];
                        let hi = bad[body_start + end + 1];
                        assert_eq!(crc16(body), u16::from(lo) | (u16::from(hi) << 8));
                    }
                }
            }
        }
    }
}

/// A deterministic pseudo random generator, so a failure is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32
    }
}

/// The property that matters on a microcontroller: no input panics.
///
/// An out-of-bounds read is not reachable here the way it was in C, so this
/// is checking the remaining failure mode. A panic in a `no_std` firmware is
/// a reset.
#[test]
fn fuzzing_never_panics() {
    let mut rng = Rng(0xC0FF_EE00_1234_5678);

    for iter in 0..200_000u32 {
        let n = 1 + (rng.next() % 64) as usize;
        let mut buf = vec![0u8; n];
        for byte in buf.iter_mut() {
            *byte = (rng.next() & 0xFF) as u8;
        }

        // Bias towards things that look like frames, so the parser is
        // actually entered rather than bailing on the first byte.
        match iter % 4 {
            0 => buf[0] = PKT_SOM,
            1 => {
                buf[0] = PKT_MARK;
                if n > 1 {
                    buf[1] = PKT_SOM;
                }
            }
            2 => {
                buf[0] = PKT_SOM;
                if n > 4 {
                    buf[4] = (rng.next() & 0x0F) as u8;
                }
            }
            _ => {}
        }

        if let Ok((frame, consumed)) = dissect(&buf) {
            assert!(consumed <= buf.len());
            assert!(frame.payload.len() <= buf.len());
        }

        let _ = dissect_stream(&buf);
    }
}

/// The scanner must always terminate, whatever it is fed, or a device on a
/// noisy bus locks up.
#[test]
fn the_stream_scanner_always_terminates() {
    let mut rng = Rng(99);

    for _ in 0..20_000 {
        let n = 1 + (rng.next() % 128) as usize;
        let mut buf = vec![0u8; n];
        for byte in buf.iter_mut() {
            *byte = match rng.next() % 3 {
                0 => PKT_SOM,
                1 => PKT_MARK,
                _ => (rng.next() & 0xFF) as u8,
            };
        }

        match dissect_stream(&buf) {
            Ok(located) => {
                assert!(located.offset <= buf.len());
                assert!(located.consumed <= buf.len());
            }
            Err((_, offset)) => assert!(offset <= buf.len()),
        }
    }
}

#[test]
fn codes_round_trip_and_name() {
    assert_eq!(Command::from(0x75), Command::KeySet);
    assert_eq!(Command::KeySet.name(), "KEYSET");
    assert_eq!(Command::from(0xA1), Command::ExtendedWrite);
    assert_eq!(Reply::from(0x46), Reply::PdCapabilities);
    assert_eq!(Reply::PdCapabilities.name(), "PDCAP");
    assert_eq!(Reply::from(0xB1), Reply::ExtendedRead);
    assert_eq!(Command::from(0x00), Command::Unknown(0x00));

    // Reader feedback is what tells us a replayed credential was accepted.
    assert!(Command::Output.is_reader_feedback());
    assert!(Command::Led.is_reader_feedback());
    assert!(!Command::Poll.is_reader_feedback());

    // 0x53 is both the start of message byte and the keypad reply. Separate
    // types are what stop those being confused.
    assert_eq!(Reply::from(0x53), Reply::Keypad);
    assert_eq!(Command::from(0x53), Command::Unknown(0x53));
}
