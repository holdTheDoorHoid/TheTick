//! Prints a canonical description of what the Rust dissector makes of each
//! hex-encoded buffer on stdin, in the same format as the C harness, so the
//! two can be compared over a shared corpus.

// A development harness, not firmware.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]

use std::io::{self, BufRead, Write};
use tick_osdp::{dissect, DissectError};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();

        let mut buf = Vec::with_capacity(trimmed.len() / 2);
        let bytes = trimmed.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            match u8::from_str_radix(&trimmed[i..i + 2], 16) {
                Ok(v) => buf.push(v),
                Err(_) => break,
            }
            i += 2;
        }

        match dissect(&buf) {
            Ok((f, consumed)) => {
                let scb = match f.security_block {
                    Some(sb) => {
                        let mut s = format!("{:02x}:", sb.kind.as_u8());
                        for b in sb.data {
                            s.push_str(&format!("{b:02x}"));
                        }
                        s
                    }
                    None => "none".to_string(),
                };
                let mut payload = String::new();
                for b in f.payload {
                    payload.push_str(&format!("{b:02x}"));
                }
                let _ = writeln!(
                    out,
                    "ok addr={} rep={} len={} seq={} crc={} scb={} id={:02x} enc={} tv={} used={} pl={}",
                    f.address,
                    u8::from(f.is_reply),
                    f.length,
                    f.sequence,
                    u8::from(f.uses_crc),
                    scb,
                    f.id,
                    u8::from(f.payload_encrypted()),
                    u8::from(f.trailer_valid),
                    consumed,
                    payload
                );
            }
            Err(DissectError::NeedMore) => {
                let _ = writeln!(out, "need_more");
            }
            Err(DissectError::NoStartOfMessage) => {
                let _ = writeln!(out, "no_som");
            }
            Err(DissectError::BadLength) => {
                let _ = writeln!(out, "bad_length");
            }
            Err(DissectError::BadSecurityBlock) => {
                let _ = writeln!(out, "bad_scb");
            }
        }
    }
}
