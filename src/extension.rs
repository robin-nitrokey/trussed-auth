// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#[allow(missing_docs)]
pub mod reply;
#[allow(missing_docs)]
pub mod request;

use serde::{Deserialize, Serialize};
use trussed::serde_extensions::{Extension, ExtensionClient, ExtensionResult};

use crate::{Pin, PinId};

/// A result returned by [`AuthClient`][].
pub type AuthResult<'a, R, C> = ExtensionResult<'a, AuthExtension, R, C>;

/// An extension that provides basic PIN handling.
///
/// See [`AuthClient`][] for the requests provided by the extension.
#[derive(Debug, Default)]
pub struct AuthExtension;

impl Extension for AuthExtension {
    type Request = AuthRequest;
    type Reply = AuthReply;
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum AuthRequest {
    HasPin(request::HasPin),
    CheckPin(request::CheckPin),
    GetPinKey(request::GetPinKey),
    SetPin(request::SetPin),
    ChangePin(request::ChangePin),
    DeletePin(request::DeletePin),
    DeleteAllPins(request::DeleteAllPins),
    PinRetries(request::PinRetries),
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum AuthReply {
    HasPin(reply::HasPin),
    CheckPin(reply::CheckPin),
    GetPinKey(reply::GetPinKey),
    SetPin(reply::SetPin),
    ChangePin(reply::ChangePin),
    DeletePin(reply::DeletePin),
    DeleteAllPins(reply::DeleteAllPins),
    PinRetries(reply::PinRetries),
}

/// Provides access to the [`AuthExtension`][].
///
/// The extension manages PINs identified by a [`PinId`][] within the namespace of this client.
/// PINs can have a retry counter.  If a retry counter is configured when setting a PIN, it is
/// decremented on every failed authentication attempt.  If the counter reaches zero, all further
/// authentication attempts fail until the PIN is reset.
///
/// The extension does not enforce any constraints on the PINs (except for the maximum length, see
/// [`MAX_PIN_LENGTH`][]).  Even empty PINs can be used.  Also, there is no authentication required
/// to set, reset or delete a PIN.  It is up to the application to enforce any policies and
/// constraints.
///
/// [`MAX_PIN_LENGTH`]: `crate::MAX_PIN_LENGTH`
pub trait AuthClient: ExtensionClient<AuthExtension> {
    /// Returns true if the PIN is set.
    fn has_pin<I: Into<PinId>>(&mut self, id: I) -> AuthResult<'_, reply::HasPin, Self> {
        self.extension(request::HasPin { id: id.into() })
    }

    /// Returns true if the provided PIN is correct and not blocked.
    ///
    /// If the PIN is not correct and a retry counter is configured, the counter is decremented.
    /// Once it reaches zero, authentication attempts for that PIN fail.  If the PIN with the given
    /// ID is not set, an error is returned.
    fn check_pin<I>(&mut self, id: I, pin: Pin) -> AuthResult<'_, reply::CheckPin, Self>
    where
        I: Into<PinId>,
    {
        self.extension(request::CheckPin { id: id.into(), pin })
    }

    /// Returns a keyid if the provided PIN is correct and not blocked.
    ///
    /// The pin must have been created with `derive_key` set to true.
    /// If the PIN is not correct and a retry counter is configured, the counter is decremented.
    /// Once it reaches zero, authentication attempts for that PIN fail.  If the PIN with the given
    /// ID is not set, an error is returned.
    fn get_pin_key<I>(&mut self, id: I, pin: Pin) -> AuthResult<'_, reply::GetPinKey, Self>
    where
        I: Into<PinId>,
    {
        self.extension(request::GetPinKey { id: id.into(), pin })
    }

    /// Sets the given PIN and resets its retry counter.
    ///
    /// If the retry counter is `None`, the number of retries is not limited and the PIN will never
    /// be blocked.
    fn set_pin<I: Into<PinId>>(
        &mut self,
        id: I,
        pin: Pin,
        retries: Option<u8>,
        derive_key: bool,
    ) -> AuthResult<'_, reply::SetPin, Self> {
        self.extension(request::SetPin {
            id: id.into(),
            pin,
            retries,
            derive_key,
        })
    }

    /// Change the given PIN and resets its retry counter.
    ///
    /// The key obtained by [`get_pin_key`](AuthClient::get_pin_key) will stay the same
    fn change_pin<I: Into<PinId>>(
        &mut self,
        id: I,
        old_pin: Pin,
        new_pin: Pin,
    ) -> AuthResult<'_, reply::ChangePin, Self> {
        self.extension(request::ChangePin {
            id: id.into(),
            old_pin,
            new_pin,
        })
    }

    /// Deletes the given PIN (if it exists).
    fn delete_pin<I: Into<PinId>>(&mut self, id: I) -> AuthResult<'_, reply::DeletePin, Self> {
        self.extension(request::DeletePin { id: id.into() })
    }

    /// Deletes all PINs for this client.
    fn delete_all_pins(&mut self) -> AuthResult<'_, reply::DeleteAllPins, Self> {
        self.extension(request::DeleteAllPins)
    }

    /// Returns the remaining retries for the given PIN.
    fn pin_retries<I: Into<PinId>>(&mut self, id: I) -> AuthResult<'_, reply::PinRetries, Self> {
        self.extension(request::PinRetries { id: id.into() })
    }
}

impl<C: ExtensionClient<AuthExtension>> AuthClient for C {}
