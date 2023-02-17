// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use serde::{Deserialize, Serialize};

use super::AuthRequest;
use crate::{Pin, PinId};

#[derive(Debug, Deserialize, Serialize)]
pub struct HasPin {
    pub id: PinId,
}

impl From<HasPin> for AuthRequest {
    fn from(request: HasPin) -> Self {
        Self::HasPin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckPin {
    pub id: PinId,
    pub pin: Pin,
}

impl From<CheckPin> for AuthRequest {
    fn from(request: CheckPin) -> Self {
        Self::CheckPin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetPinKey {
    pub id: PinId,
    pub pin: Pin,
}

impl From<GetPinKey> for AuthRequest {
    fn from(request: GetPinKey) -> Self {
        Self::GetPinKey(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetPin {
    pub id: PinId,
    pub pin: Pin,
    pub retries: Option<u8>,
    /// If true, the PIN can be used to wrap/unwrap an application key
    pub derive_key: bool,
}

impl From<SetPin> for AuthRequest {
    fn from(request: SetPin) -> Self {
        Self::SetPin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeletePin {
    pub id: PinId,
}

impl From<DeletePin> for AuthRequest {
    fn from(request: DeletePin) -> Self {
        Self::DeletePin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteAllPins;

impl From<DeleteAllPins> for AuthRequest {
    fn from(request: DeleteAllPins) -> Self {
        Self::DeleteAllPins(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PinRetries {
    pub id: PinId,
}

impl From<PinRetries> for AuthRequest {
    fn from(request: PinRetries) -> Self {
        Self::PinRetries(request)
    }
}
