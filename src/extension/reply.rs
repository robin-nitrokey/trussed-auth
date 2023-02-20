// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use serde::{Deserialize, Serialize};
use trussed::{
    error::{Error, Result},
    types::KeyId,
};

use super::AuthReply;

#[derive(Debug, Deserialize, Serialize)]
#[must_use]
pub struct HasPin {
    pub has_pin: bool,
}

impl From<HasPin> for AuthReply {
    fn from(reply: HasPin) -> Self {
        Self::HasPin(reply)
    }
}

impl TryFrom<AuthReply> for HasPin {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::HasPin(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[must_use]
pub struct CheckPin {
    pub success: bool,
}

impl From<CheckPin> for AuthReply {
    fn from(reply: CheckPin) -> Self {
        Self::CheckPin(reply)
    }
}

impl TryFrom<AuthReply> for CheckPin {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::CheckPin(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[must_use]
pub struct GetPinKey {
    /// None means the check failed
    pub result: Option<KeyId>,
}

impl From<GetPinKey> for AuthReply {
    fn from(reply: GetPinKey) -> Self {
        Self::GetPinKey(reply)
    }
}

impl TryFrom<AuthReply> for GetPinKey {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::GetPinKey(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetPin;

impl From<SetPin> for AuthReply {
    fn from(reply: SetPin) -> Self {
        Self::SetPin(reply)
    }
}

impl TryFrom<AuthReply> for SetPin {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::SetPin(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeletePin;

impl From<DeletePin> for AuthReply {
    fn from(reply: DeletePin) -> Self {
        Self::DeletePin(reply)
    }
}

impl TryFrom<AuthReply> for DeletePin {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::DeletePin(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteAllPins;

impl From<DeleteAllPins> for AuthReply {
    fn from(reply: DeleteAllPins) -> Self {
        Self::DeleteAllPins(reply)
    }
}

impl TryFrom<AuthReply> for DeleteAllPins {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::DeleteAllPins(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[must_use]
pub struct PinRetries {
    pub retries: Option<u8>,
}

impl From<PinRetries> for AuthReply {
    fn from(reply: PinRetries) -> Self {
        Self::PinRetries(reply)
    }
}

impl TryFrom<AuthReply> for PinRetries {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::PinRetries(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}
