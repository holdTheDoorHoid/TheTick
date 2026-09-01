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

//! Command, reply and security block codes from SIA OSDP v2.2.2.
//!
//! These are separate types rather than bare `u8` constants so that a command
//! code cannot be compared against a reply code by accident. In the C version
//! both were plain integers in the same numeric space, and `0x53` is both the
//! start of message byte and the keypad reply.

/// A command, sent by the control panel to a peripheral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// Keep the link alive and collect any pending event.
    Poll,
    /// Ask the peripheral to identify itself.
    Id,
    /// Ask the peripheral what it can do.
    Capabilities,
    /// Local status report.
    LocalStatus,
    /// Input status report.
    InputStatus,
    /// Output status report.
    OutputStatus,
    /// Reader status report.
    ReaderStatus,
    /// Drive an output, which on an access panel is the door strike.
    Output,
    /// Drive a reader LED.
    Led,
    /// Drive the reader buzzer.
    Buzzer,
    /// Display text on the reader.
    Text,
    /// Set the reader mode.
    ReaderMode,
    /// Set the date and time.
    TimeSet,
    /// Change the communication settings.
    CommSet,
    /// Read a biometric template.
    BioRead,
    /// Match against a biometric template.
    BioMatch,
    /// Install a secure channel base key.
    KeySet,
    /// Begin a secure channel handshake.
    Challenge,
    /// Complete a secure channel handshake.
    ServerCryptogram,
    /// Announce the controller's receive buffer size.
    MaxReplySize,
    /// Transfer a file.
    FileTransfer,
    /// Manufacturer specific command.
    Manufacturer,
    /// Transparent mode write, for smart card passthrough.
    ExtendedWrite,
    /// Abort the current operation.
    Abort,
    /// PIV data request.
    PivData,
    /// Generic authentication challenge.
    GenericAuth,
    /// Challenge and response authentication.
    ChallengeResponseAuth,
    /// Keep a smart card powered.
    KeepActive,
    /// Something not in the specification, or not in this list.
    Unknown(u8),
}

impl From<u8> for Command {
    fn from(value: u8) -> Self {
        match value {
            0x60 => Self::Poll,
            0x61 => Self::Id,
            0x62 => Self::Capabilities,
            0x64 => Self::LocalStatus,
            0x65 => Self::InputStatus,
            0x66 => Self::OutputStatus,
            0x67 => Self::ReaderStatus,
            0x68 => Self::Output,
            0x69 => Self::Led,
            0x6A => Self::Buzzer,
            0x6B => Self::Text,
            0x6C => Self::ReaderMode,
            0x6D => Self::TimeSet,
            0x6E => Self::CommSet,
            0x73 => Self::BioRead,
            0x74 => Self::BioMatch,
            0x75 => Self::KeySet,
            0x76 => Self::Challenge,
            0x77 => Self::ServerCryptogram,
            0x7B => Self::MaxReplySize,
            0x7C => Self::FileTransfer,
            0x80 => Self::Manufacturer,
            0xA1 => Self::ExtendedWrite,
            0xA2 => Self::Abort,
            0xA3 => Self::PivData,
            0xA4 => Self::GenericAuth,
            0xA5 => Self::ChallengeResponseAuth,
            0xA7 => Self::KeepActive,
            other => Self::Unknown(other),
        }
    }
}

impl Command {
    /// Short name, for logs and the interface.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Poll => "POLL",
            Self::Id => "ID",
            Self::Capabilities => "CAP",
            Self::LocalStatus => "LSTAT",
            Self::InputStatus => "ISTAT",
            Self::OutputStatus => "OSTAT",
            Self::ReaderStatus => "RSTAT",
            Self::Output => "OUT",
            Self::Led => "LED",
            Self::Buzzer => "BUZ",
            Self::Text => "TEXT",
            Self::ReaderMode => "RMODE",
            Self::TimeSet => "TDSET",
            Self::CommSet => "COMSET",
            Self::BioRead => "BIOREAD",
            Self::BioMatch => "BIOMATCH",
            Self::KeySet => "KEYSET",
            Self::Challenge => "CHLNG",
            Self::ServerCryptogram => "SCRYPT",
            Self::MaxReplySize => "ACURXSIZE",
            Self::FileTransfer => "FILETRANSFER",
            Self::Manufacturer => "MFG",
            Self::ExtendedWrite => "XWR",
            Self::Abort => "ABORT",
            Self::PivData => "PIVDATA",
            Self::GenericAuth => "GENAUTH",
            Self::ChallengeResponseAuth => "CRAUTH",
            Self::KeepActive => "KEEPACTIVE",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    /// Whether this command tells the reader to signal an outcome to whoever
    /// is standing at the door.
    ///
    /// After a credential is presented, these are the controller's answer,
    /// which is what makes the result of a replay directly observable.
    #[must_use]
    pub fn is_reader_feedback(self) -> bool {
        matches!(self, Self::Output | Self::Led | Self::Buzzer | Self::Text)
    }
}

/// A reply, sent by a peripheral back to the control panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reply {
    /// Acknowledged.
    Ack,
    /// Negative acknowledgement.
    Nak,
    /// Identity report.
    PdId,
    /// Capability report.
    PdCapabilities,
    /// Local status report.
    LocalStatus,
    /// Input status report.
    InputStatus,
    /// Output status report.
    OutputStatus,
    /// Reader status report.
    ReaderStatus,
    /// A card was presented; this carries the credential.
    RawCardData,
    /// Formatted card data, deprecated by the specification.
    FormattedCardData,
    /// Keypad entry.
    Keypad,
    /// Communication settings report.
    CommSettings,
    /// Biometric read result.
    BioRead,
    /// Biometric match result.
    BioMatch,
    /// Challenge response, carrying the peripheral's cryptogram.
    ChallengeResponse,
    /// Initial reply MAC.
    InitialRMac,
    /// Busy, try again.
    Busy,
    /// File transfer status.
    FileTransferStatus,
    /// PIV data reply.
    PivData,
    /// Generic authentication reply.
    GenericAuth,
    /// Challenge response authentication reply.
    ChallengeResponseAuth,
    /// Manufacturer specific status.
    ManufacturerStatus,
    /// Manufacturer specific error.
    ManufacturerError,
    /// Manufacturer specific reply.
    ManufacturerReply,
    /// Transparent mode read, for smart card passthrough.
    ExtendedRead,
    /// Something not in the specification, or not in this list.
    Unknown(u8),
}

impl From<u8> for Reply {
    fn from(value: u8) -> Self {
        match value {
            0x40 => Self::Ack,
            0x41 => Self::Nak,
            0x45 => Self::PdId,
            0x46 => Self::PdCapabilities,
            0x48 => Self::LocalStatus,
            0x49 => Self::InputStatus,
            0x4A => Self::OutputStatus,
            0x4B => Self::ReaderStatus,
            0x50 => Self::RawCardData,
            0x51 => Self::FormattedCardData,
            0x53 => Self::Keypad,
            0x54 => Self::CommSettings,
            0x57 => Self::BioRead,
            0x58 => Self::BioMatch,
            0x76 => Self::ChallengeResponse,
            0x78 => Self::InitialRMac,
            0x79 => Self::Busy,
            0x7A => Self::FileTransferStatus,
            0x80 => Self::PivData,
            0x81 => Self::GenericAuth,
            0x82 => Self::ChallengeResponseAuth,
            0x83 => Self::ManufacturerStatus,
            0x84 => Self::ManufacturerError,
            0x90 => Self::ManufacturerReply,
            0xB1 => Self::ExtendedRead,
            other => Self::Unknown(other),
        }
    }
}

impl Reply {
    /// Short name, for logs and the interface.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Ack => "ACK",
            Self::Nak => "NAK",
            Self::PdId => "PDID",
            Self::PdCapabilities => "PDCAP",
            Self::LocalStatus => "LSTATR",
            Self::InputStatus => "ISTATR",
            Self::OutputStatus => "OSTATR",
            Self::ReaderStatus => "RSTATR",
            Self::RawCardData => "RAW",
            Self::FormattedCardData => "FMT",
            Self::Keypad => "KEYPAD",
            Self::CommSettings => "COM",
            Self::BioRead => "BIOREADR",
            Self::BioMatch => "BIOMATCHR",
            Self::ChallengeResponse => "CCRYPT",
            Self::InitialRMac => "RMAC_I",
            Self::Busy => "BUSY",
            Self::FileTransferStatus => "FTSTAT",
            Self::PivData => "PIVDATAR",
            Self::GenericAuth => "GENAUTHR",
            Self::ChallengeResponseAuth => "CRAUTHR",
            Self::ManufacturerStatus => "MFGSTATR",
            Self::ManufacturerError => "MFGERRR",
            Self::ManufacturerReply => "MFGREP",
            Self::ExtendedRead => "XRD",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    /// Whether this reply carries a credential.
    #[must_use]
    pub fn carries_credential(self) -> bool {
        matches!(
            self,
            Self::RawCardData | Self::FormattedCardData | Self::Keypad
        )
    }
}

/// Security block types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityBlockType {
    /// Controller to peripheral, the challenge.
    Challenge,
    /// Peripheral to controller, the challenge response.
    ChallengeResponse,
    /// Controller to peripheral, the server cryptogram.
    ServerCryptogram,
    /// Peripheral to controller, the initial reply MAC.
    ServerCryptogramResponse,
    /// Controller to peripheral, authenticated but not encrypted.
    CommandNoEncryption,
    /// Peripheral to controller, authenticated but not encrypted.
    ReplyNoEncryption,
    /// Controller to peripheral, authenticated and encrypted.
    CommandWithEncryption,
    /// Peripheral to controller, authenticated and encrypted.
    ReplyWithEncryption,
    /// Not a block type this version knows about.
    Unknown(u8),
}

impl From<u8> for SecurityBlockType {
    fn from(value: u8) -> Self {
        match value {
            0x11 => Self::Challenge,
            0x12 => Self::ChallengeResponse,
            0x13 => Self::ServerCryptogram,
            0x14 => Self::ServerCryptogramResponse,
            0x15 => Self::CommandNoEncryption,
            0x16 => Self::ReplyNoEncryption,
            0x17 => Self::CommandWithEncryption,
            0x18 => Self::ReplyWithEncryption,
            other => Self::Unknown(other),
        }
    }
}

impl SecurityBlockType {
    /// The raw byte this type came from.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Challenge => 0x11,
            Self::ChallengeResponse => 0x12,
            Self::ServerCryptogram => 0x13,
            Self::ServerCryptogramResponse => 0x14,
            Self::CommandNoEncryption => 0x15,
            Self::ReplyNoEncryption => 0x16,
            Self::CommandWithEncryption => 0x17,
            Self::ReplyWithEncryption => 0x18,
            Self::Unknown(other) => other,
        }
    }

    /// Authenticated but not encrypted. Bishop Fox call these null ciphers:
    /// the frame is protected against tampering and readable by anyone.
    #[must_use]
    pub fn is_null_cipher(self) -> bool {
        matches!(self, Self::CommandNoEncryption | Self::ReplyNoEncryption)
    }
}

/// Capability function codes, needed to read a capability reply.
pub mod capability {
    /// Whether the peripheral can do AES on the wire. A compliance level of
    /// zero here is what a downgrade attack forges.
    pub const COMMUNICATION_SECURITY: u8 = 9;
    /// Card data format support.
    pub const CARD_DATA_FORMAT: u8 = 3;
    /// Number of readers attached.
    pub const READERS: u8 = 13;
}
