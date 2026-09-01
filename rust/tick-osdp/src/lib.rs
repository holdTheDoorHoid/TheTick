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

//! OSDP frame dissection.
//!
//! This is the code that reads bytes off a wire an attacker can reach, which
//! makes it the part of the firmware most worth writing in a language that
//! will not let it read past the end of a buffer.
//!
//! Three properties are enforced by the compiler rather than by review:
//!
//! - `unsafe` is forbidden workspace-wide, so there is no escape hatch.
//! - Every borrow of the input is a slice, so an out-of-bounds read is a
//!   panic at worst and, with `indexing_slicing` denied, does not compile at
//!   all in the places that matter.
//! - A security block is an [`Option`], so its contents cannot be read
//!   without first establishing that one is present. In the C version those
//!   were a `bool` and some fields beside it, and nothing stopped a caller
//!   reading the fields when the bool was false.
//!
//! The frame layout follows SIA OSDP v2.2.2, cross-checked against libosdp:
//!
//! ```text
//! [0xFF]      optional MARK byte
//! 0x53        SOM
//! address     bit 7 set means a reply from the peripheral
//! len_lsb     total length, SOM through trailer, excluding MARK
//! len_msb
//! control     bits 0-1 sequence, bit 2 CRC (else checksum), bit 3 SCB
//! [scb]       security block: length, type, then type-specific data
//! id          command or reply code
//! payload
//! trailer     CRC-16 (2 bytes) or a one byte checksum
//! ```

#![no_std]

pub mod codes;

pub use codes::{Command, Reply, SecurityBlockType};

/// Optional byte some controllers send before the start of message.
pub const PKT_MARK: u8 = 0xFF;
/// Start of message.
pub const PKT_SOM: u8 = 0x53;
/// SOM, address, two length bytes and the control byte.
pub const HEADER_LEN: usize = 5;
/// Longest frame this dissector will accept.
pub const MAX_FRAME: usize = 1024;

const CONTROL_SEQUENCE: u8 = 0x03;
const CONTROL_CRC: u8 = 0x04;
const CONTROL_SCB: u8 = 0x08;

/// Why a buffer could not be read as a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DissectError {
    /// Not enough bytes yet. Keep them and try again with more.
    NeedMore,
    /// No start of message here.
    NoStartOfMessage,
    /// The declared length cannot describe a real frame.
    BadLength,
    /// The security block does not fit inside the frame.
    BadSecurityBlock,
}

/// The security block, present only when the control byte says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityBlock<'a> {
    /// Raw block type byte.
    pub kind: SecurityBlockType,
    /// Block contents, excluding the length and type bytes.
    pub data: &'a [u8],
}

impl SecurityBlock<'_> {
    /// Whether this block means the payload is ciphertext.
    ///
    /// Only two of the eight block types actually encrypt. The rest
    /// authenticate at most, which is why passive monitoring of a "secure"
    /// bus is so often still possible.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        matches!(
            self.kind,
            SecurityBlockType::CommandWithEncryption
                | SecurityBlockType::ReplyWithEncryption
        )
    }

    /// Whether this block is part of the handshake rather than data.
    #[must_use]
    pub fn is_handshake(&self) -> bool {
        matches!(
            self.kind,
            SecurityBlockType::Challenge
                | SecurityBlockType::ChallengeResponse
                | SecurityBlockType::ServerCryptogram
                | SecurityBlockType::ServerCryptogramResponse
        )
    }

    /// Whether the handshake declared the specification's default key.
    ///
    /// The first byte of a challenge block is zero when SCBK-D is in use.
    /// That key is printed in the specification, so a channel built on it
    /// protects nothing, and noticing costs no cryptography at all.
    #[must_use]
    pub fn uses_default_key(&self) -> bool {
        self.is_handshake() && matches!(self.data.first(), Some(0))
    }
}

/// One parsed frame, borrowing from the buffer it was read out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// A MARK byte preceded the start of message.
    pub has_mark: bool,
    /// Seven bit peripheral address, reply flag removed.
    pub address: u8,
    /// True when the peripheral sent this, false when the controller did.
    pub is_reply: bool,
    /// Length as declared in the header.
    pub length: u16,
    /// Sequence number, 0 to 3.
    pub sequence: u8,
    /// False means the weaker one byte checksum was used.
    pub uses_crc: bool,
    /// Present only when the control byte set the security block flag.
    pub security_block: Option<SecurityBlock<'a>>,
    /// Command code when this is a command, reply code when it is a reply.
    pub id: u8,
    /// Everything between the id byte and the trailer.
    pub payload: &'a [u8],
    /// Whether the CRC or checksum matched.
    ///
    /// Deliberately reported rather than turned into an error: a monitor
    /// wants to count corrupt frames, and a frame that fails this check must
    /// never drive a finding.
    pub trailer_valid: bool,
}

impl Frame<'_> {
    /// The command this frame carries, if it is a command.
    #[must_use]
    pub fn command(&self) -> Option<Command> {
        if self.is_reply {
            None
        } else {
            Some(Command::from(self.id))
        }
    }

    /// The reply this frame carries, if it is a reply.
    #[must_use]
    pub fn reply(&self) -> Option<Reply> {
        if self.is_reply {
            Some(Reply::from(self.id))
        } else {
            None
        }
    }

    /// Whether the payload is ciphertext.
    #[must_use]
    pub fn payload_encrypted(&self) -> bool {
        self.security_block.is_some_and(|sb| sb.is_encrypted())
    }

    /// Human readable name for the command or reply.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match (self.command(), self.reply()) {
            (Some(c), _) => c.name(),
            (_, Some(r)) => r.name(),
            _ => "UNKNOWN",
        }
    }
}

/// The OSDP CRC-16, seeded `0x1D0F`.
///
/// This is CRC-16/AUG-CCITT. Its published check value over `"123456789"` is
/// `0xE5CC`, which the tests assert against so a transcription slip cannot
/// hide behind a round trip through our own encoder.
#[must_use]
pub fn crc16(buf: &[u8]) -> u16 {
    let mut seed: u16 = 0x1D0F;
    for byte in buf {
        seed = seed.swap_bytes();
        seed ^= u16::from(*byte);
        seed ^= (seed & 0x00FF) >> 4;
        seed ^= seed << 12;
        seed ^= (seed & 0x00FF) << 5;
    }
    seed
}

/// The one byte checksum used when the CRC control bit is clear.
#[must_use]
pub fn checksum(buf: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for byte in buf {
        sum = sum.wrapping_add(*byte);
    }
    (!sum).wrapping_add(1)
}

/// Parse one frame starting at the beginning of `buf`.
///
/// Returns the frame and how many bytes it occupied. The frame borrows from
/// `buf`, so the compiler will not let it outlive the buffer.
///
/// # Errors
///
/// Returns [`DissectError`] describing why the bytes are not a frame. A
/// failed trailer is not an error: it comes back as a frame with
/// [`Frame::trailer_valid`] false, so a caller can count it.
pub fn dissect(buf: &[u8]) -> Result<(Frame<'_>, usize), DissectError> {
    let (has_mark, rest) = match buf.split_first() {
        Some((&PKT_MARK, tail)) => (true, tail),
        Some(_) => (false, buf),
        None => return Err(DissectError::NeedMore),
    };

    let offset = usize::from(has_mark);

    match rest.first() {
        None => return Err(DissectError::NeedMore),
        Some(&PKT_SOM) => {}
        Some(_) => return Err(DissectError::NoStartOfMessage),
    }

    let header = rest.get(..HEADER_LEN).ok_or(DissectError::NeedMore)?;

    // Indices here are into a slice already proven to be HEADER_LEN long.
    let address_byte = *header.get(1).ok_or(DissectError::NeedMore)?;
    let len_lsb = *header.get(2).ok_or(DissectError::NeedMore)?;
    let len_msb = *header.get(3).ok_or(DissectError::NeedMore)?;
    let control = *header.get(4).ok_or(DissectError::NeedMore)?;

    let length = u16::from(len_lsb) | (u16::from(len_msb) << 8);
    let length_usize = usize::from(length);

    let uses_crc = control & CONTROL_CRC != 0;
    let has_scb = control & CONTROL_SCB != 0;
    let trailer_len: usize = if uses_crc { 2 } else { 1 };

    // Establish the minimum before any subtraction. The C version had to be
    // careful here by hand; a wrapped length there would have produced an
    // enormous payload slice.
    let minimum = HEADER_LEN
        .checked_add(1)
        .and_then(|n| n.checked_add(trailer_len))
        .ok_or(DissectError::BadLength)?;
    if length_usize < minimum || length_usize > MAX_FRAME {
        return Err(DissectError::BadLength);
    }

    let frame_bytes = rest.get(..length_usize).ok_or(DissectError::NeedMore)?;

    let (security_block, body_start) = if has_scb {
        let scb_len = usize::from(*frame_bytes.get(HEADER_LEN).ok_or(DissectError::BadSecurityBlock)?);
        if scb_len < 2 {
            return Err(DissectError::BadSecurityBlock);
        }
        let scb_end = HEADER_LEN
            .checked_add(scb_len)
            .ok_or(DissectError::BadSecurityBlock)?;
        // The block, an id byte and the trailer all have to fit.
        let needed = scb_end
            .checked_add(1)
            .and_then(|n| n.checked_add(trailer_len))
            .ok_or(DissectError::BadSecurityBlock)?;
        if needed > length_usize {
            return Err(DissectError::BadSecurityBlock);
        }

        let kind = SecurityBlockType::from(
            *frame_bytes
                .get(HEADER_LEN.checked_add(1).ok_or(DissectError::BadSecurityBlock)?)
                .ok_or(DissectError::BadSecurityBlock)?,
        );
        let data = frame_bytes
            .get(HEADER_LEN.checked_add(2).ok_or(DissectError::BadSecurityBlock)?..scb_end)
            .ok_or(DissectError::BadSecurityBlock)?;

        (Some(SecurityBlock { kind, data }), scb_end)
    } else {
        (None, HEADER_LEN)
    };

    let id = *frame_bytes.get(body_start).ok_or(DissectError::BadLength)?;

    let payload_start = body_start.checked_add(1).ok_or(DissectError::BadLength)?;
    let payload_end = length_usize
        .checked_sub(trailer_len)
        .ok_or(DissectError::BadLength)?;
    let payload = frame_bytes
        .get(payload_start..payload_end)
        .ok_or(DissectError::BadLength)?;

    let trailer_valid = if uses_crc {
        let body = frame_bytes.get(..payload_end).ok_or(DissectError::BadLength)?;
        let lo = *frame_bytes.get(payload_end).ok_or(DissectError::BadLength)?;
        let hi = *frame_bytes
            .get(payload_end.checked_add(1).ok_or(DissectError::BadLength)?)
            .ok_or(DissectError::BadLength)?;
        crc16(body) == (u16::from(lo) | (u16::from(hi) << 8))
    } else {
        let body = frame_bytes.get(..payload_end).ok_or(DissectError::BadLength)?;
        let sum = *frame_bytes.get(payload_end).ok_or(DissectError::BadLength)?;
        checksum(body) == sum
    };

    let frame = Frame {
        has_mark,
        address: address_byte & 0x7F,
        is_reply: address_byte & 0x80 != 0,
        length,
        sequence: control & CONTROL_SEQUENCE,
        uses_crc,
        security_block,
        id,
        payload,
        trailer_valid,
    };

    let consumed = offset
        .checked_add(length_usize)
        .ok_or(DissectError::BadLength)?;
    Ok((frame, consumed))
}

/// Where a frame was found in a larger buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Located<'a> {
    /// The frame.
    pub frame: Frame<'a>,
    /// How many bytes of leading noise were skipped.
    pub offset: usize,
    /// How many bytes the frame itself occupied, from `offset`.
    pub consumed: usize,
}

/// Find and parse the next frame anywhere in `buf`, skipping leading noise.
///
/// A bus is a shared medium and a listener joins mid-conversation, so
/// resynchronising is the normal case rather than an error path.
///
/// # Errors
///
/// [`DissectError::NeedMore`] means a frame started but is not yet complete;
/// keep the tail from the reported offset. Anything else means nothing usable
/// was found.
pub fn dissect_stream(buf: &[u8]) -> Result<Located<'_>, (DissectError, usize)> {
    let mut last = DissectError::NoStartOfMessage;

    for (index, window) in buf.windows(1).enumerate() {
        let byte = match window.first() {
            Some(b) => *b,
            None => continue,
        };
        if byte != PKT_SOM && byte != PKT_MARK {
            continue;
        }

        let tail = match buf.get(index..) {
            Some(t) => t,
            None => continue,
        };

        // A MARK only starts a frame when a SOM follows it.
        if byte == PKT_MARK && !matches!(tail.get(1), Some(&PKT_SOM)) {
            continue;
        }

        match dissect(tail) {
            Ok((frame, consumed)) => {
                return Ok(Located {
                    frame,
                    offset: index,
                    consumed,
                })
            }
            Err(DissectError::NeedMore) => {
                return Err((DissectError::NeedMore, index));
            }
            Err(other) => last = other,
        }
    }

    Err((last, buf.len()))
}
