// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

// #![no_std]
#![warn(
    missing_debug_implementations,
    missing_docs,
    non_ascii_idents,
    trivial_casts,
    unused,
    unused_qualifications,
    clippy::expect_used,
    clippy::unwrap_used
)]
#![deny(unsafe_code)]

//! A Trussed API extension for authentication and a backend that implements it.
//!
//! This crate contains an API extension for [Trussed][], [`AuthExtension`][].  The extension
//! currently provides basic PIN handling with retry counters.  Applications can access it using
//! the [`AuthClient`][] trait.
//!
//! This crate also contains [`AuthBackend`][], an implementation of the auth extension that stores
//! PINs in the filesystem.
//!
//! # Examples
//!
//! ```
//! use trussed::{Bytes, syscall};
//! use trussed_auth::{AuthClient, PinId};
//!
//! #[repr(u8)]
//! enum Pin {
//!     User = 0,
//! }
//!
//! impl From<Pin> for PinId {
//!     fn from(pin: Pin) -> Self {
//!         (pin as u8).into()
//!     }
//! }
//!
//! fn authenticate_user<C: AuthClient>(client: &mut C, pin: Option<&[u8]>) -> bool {
//!     if !syscall!(client.has_pin(Pin::User)).has_pin {
//!         // no PIN set
//!         return true;
//!     }
//!     let Some(pin) = pin else {
//!         // PIN is set but not provided
//!         return false;
//!     };
//!     let Ok(pin) = Bytes::from_slice(pin) else {
//!         // provided PIN is too long
//!         return false;
//!     };
//!     // check PIN
//!     syscall!(client.check_pin(Pin::User, pin)).success
//! }
//! ```
//!
//! [Trussed]: https://docs.rs/trussed

mod backend;
mod extension;

use serde::{Deserialize, Serialize};
use trussed::{
    config::MAX_SHORT_DATA_LENGTH,
    types::{Bytes, PathBuf},
};

pub use backend::{AuthBackend, AuthContext, MAX_HW_KEY_LEN};
pub use extension::{
    reply, request, AuthClient, AuthExtension, AuthReply, AuthRequest, AuthResult,
};

/// The maximum length of a PIN.
pub const MAX_PIN_LENGTH: usize = MAX_SHORT_DATA_LENGTH;

/// A PIN.
pub type Pin = Bytes<MAX_PIN_LENGTH>;

const PIN_PATH: &str = "backend/auth/pin";
const SALT_PATH: &str = "backend/auth/salt";

/// The ID of a PIN within the namespace of a client.
///
/// It is recommended that applications use an enum that implements `Into<PinId>`.
///
/// # Examples
///
/// ```
/// use trussed_auth::PinId;
///
/// #[repr(u8)]
/// enum Pin {
///     User = 0,
///     Admin = 1,
///     ResetCode = 2,
/// }
///
/// impl From<Pin> for PinId {
///     fn from(pin: Pin) -> Self {
///         (pin as u8).into()
///     }
/// }
/// ```
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize,
)]
pub struct PinId(u8);

impl PinId {
    fn path(&self) -> PathBuf {
        let mut path = PathBuf::from(PIN_PATH);
        path.push(&PathBuf::from(&self.hex()));
        path
    }

    fn hex(&self) -> [u8; 2] {
        const CHARS: &[u8; 16] = b"0123456789abcdef";
        [
            CHARS[usize::from(self.0 >> 4)],
            CHARS[usize::from(self.0 & 0xf)],
        ]
    }
}

impl From<u8> for PinId {
    fn from(id: u8) -> Self {
        Self(id)
    }
}

impl From<PinId> for u8 {
    fn from(id: PinId) -> Self {
        id.0
    }
}
