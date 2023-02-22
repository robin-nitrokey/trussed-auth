// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

mod data;

use core::fmt;

use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use trussed::{
    backend::Backend,
    error::Result,
    key::{Kind, Secrecy},
    platform::Platform,
    serde_extensions::ExtensionImpl,
    service::{Keystore, ServiceResources},
    store::filestore::Filestore,
    types::{CoreContext, Location, PathBuf},
    Bytes,
};

use crate::{
    extension::{reply, AuthExtension, AuthReply, AuthRequest},
    PIN_PATH, SALT_PATH,
};
use data::{Key, PinData, Salt, KEY_LEN, SALT_LEN};

/// max accepted length for the hardware initial key material
pub const MAX_HW_KEY_LEN: usize = 64;

#[derive(Clone)]
enum HardwareKey {
    None,
    Raw(Bytes<MAX_HW_KEY_LEN>),
    Extracted(Hkdf<Sha256>),
}

impl fmt::Debug for HardwareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.debug_tuple("None").finish(),
            Self::Raw(_) => f.debug_tuple("Raw").field(&"[redacted]").finish(),
            Self::Extracted(_) => f.debug_tuple("Raw").field(&"[redacted]").finish(),
        }
    }
}

/// A basic implementation of the [`AuthExtension`][].
///
/// This implementation stores PINs together with their retry counters on the filesystem.  PINs are
/// hashed with SHA-256 using a salt that is generated per PIN.
#[derive(Clone, Debug)]
pub struct AuthBackend {
    location: Location,
    hw_key: HardwareKey,
}

impl AuthBackend {
    /// Creates a new `AuthBackend` using the given storage location for the PINs.
    pub fn new(location: Location) -> Self {
        Self {
            location,
            hw_key: HardwareKey::None,
        }
    }
    /// Creates a new `AuthBackend` with a given key.
    ///
    /// This key is used to strengthen key generation from the pins
    pub fn with_hw_key(location: Location, hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
        Self {
            location,
            hw_key: HardwareKey::Raw(hw_key),
        }
    }

    fn get_global_salt<R: CryptoRng + RngCore>(
        &self,
        trussed_filestore: &mut impl Filestore,
        rng: &mut R,
    ) -> Result<Salt, Error> {
        let path = PathBuf::from(SALT_PATH);
        trussed_filestore
            .read(&path, self.location)
            .or_else(|_| {
                if trussed_filestore.exists(&path, self.location) {
                    return Err(Error::ReadFailed);
                }

                let mut salt = Bytes::<SALT_LEN>::default();
                salt.resize_to_capacity();
                rng.fill_bytes(&mut salt);
                trussed_filestore
                    .write(&path, self.location, &salt)
                    .or(Err(Error::WriteFailed))
                    .and(Ok(salt))
            })
            .and_then(|b| (**b).try_into().or(Err(Error::ReadFailed)))
    }

    fn extract<R: CryptoRng + RngCore>(
        &mut self,
        trussed_filestore: &mut impl Filestore,
        ikm: Option<Bytes<MAX_HW_KEY_LEN>>,
        rng: &mut R,
    ) -> Result<&Hkdf<Sha256>, Error> {
        let ikm: &[u8] = ikm.as_deref().map(|i| &**i).unwrap_or(&[]);
        let salt = self.get_global_salt(trussed_filestore, rng)?;
        let kdf = Hkdf::new(Some(&*salt), ikm);
        self.hw_key = HardwareKey::Extracted(kdf);
        match &self.hw_key {
            HardwareKey::Extracted(kdf) => Ok(kdf),
            // hw_key was just set to Extracted
            _ => unreachable!(),
        }
    }

    fn expand(kdf: &Hkdf<Sha256>, client_id: &PathBuf) -> Key {
        let mut out = Key::default();
        #[allow(clippy::expect_used)]
        kdf.expand(client_id.as_ref().as_bytes(), &mut *out)
            .expect("Out data is always valid");
        out
    }

    fn generate_app_key<R: CryptoRng + RngCore>(
        &mut self,
        client_id: PathBuf,
        trussed_filestore: &mut impl Filestore,
        rng: &mut R,
    ) -> Result<Key, Error> {
        Ok(match &self.hw_key {
            HardwareKey::Extracted(okm) => Self::expand(okm, &client_id),
            HardwareKey::Raw(hw_k) => {
                let kdf = self.extract(trussed_filestore, Some(hw_k.clone()), rng)?;
                Self::expand(kdf, &client_id)
            }
            HardwareKey::None => {
                let kdf = self.extract(trussed_filestore, None, rng)?;
                Self::expand(kdf, &client_id)
            }
        })
    }

    fn get_app_key<R: CryptoRng + RngCore>(
        &mut self,
        client_id: PathBuf,
        trussed_filestore: &mut impl Filestore,
        ctx: &mut AuthContext,
        rng: &mut R,
    ) -> Result<Key, Error> {
        if let Some(app_key) = ctx.application_key {
            return Ok(app_key);
        }

        let app_key = self.generate_app_key(client_id, trussed_filestore, rng)?;
        ctx.application_key = Some(app_key);
        Ok(app_key)
    }
}

/// Per-client context for [`AuthBackend`][]
#[derive(Default, Debug)]
pub struct AuthContext {
    application_key: Option<Key>,
}

impl Backend for AuthBackend {
    type Context = AuthContext;
}

impl ExtensionImpl<AuthExtension> for AuthBackend {
    fn extension_request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        ctx: &mut AuthContext,
        request: &AuthRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<AuthReply> {
        let fs = &mut resources.filestore(core_ctx);
        let trussed_fs = &mut resources.trussed_filestore();
        let rng = &mut resources.rng()?;
        let client_id = core_ctx.path.clone();
        let keystore = &mut resources.keystore(core_ctx)?;
        match request {
            AuthRequest::HasPin(request) => {
                let has_pin = fs.exists(&request.id.path(), self.location);
                Ok(reply::HasPin { has_pin }.into())
            }
            AuthRequest::CheckPin(request) => {
                let success = PinData::load(fs, self.location, request.id)?.write(
                    fs,
                    self.location,
                    |data| {
                        data.check_pin(&request.pin, || {
                            self.get_app_key(client_id, trussed_fs, ctx, rng)
                        })
                    },
                )??;
                Ok(reply::CheckPin { success }.into())
            }
            AuthRequest::GetPinKey(request) => {
                let application_key =
                    self.get_app_key(core_ctx.path.clone(), trussed_fs, ctx, rng)?;
                let verification = PinData::load(fs, self.location, request.id)?.write(
                    fs,
                    self.location,
                    |data| data.get_pin_key(&request.pin, &application_key),
                )??;
                if let Some(k) = verification {
                    let key_id = keystore.store_key(
                        Location::Volatile,
                        Secrecy::Secret,
                        Kind::Symmetric(KEY_LEN),
                        &*k,
                    )?;
                    Ok(reply::GetPinKey {
                        result: Some(key_id),
                    }
                    .into())
                } else {
                    Ok(reply::GetPinKey { result: None }.into())
                }
            }
            AuthRequest::ChangePin(request) => {
                let success = PinData::load(fs, self.location, request.id)?.write(
                    fs,
                    self.location,
                    |data| {
                        data.change_pin(
                            &request.old_pin,
                            &request.new_pin,
                            move |rng| self.get_app_key(client_id, trussed_fs, ctx, rng),
                            rng,
                        )
                    },
                )??;
                Ok(reply::ChangePin { success }.into())
            }
            AuthRequest::SetPin(request) => {
                let maybe_app_key = if request.derive_key {
                    Some(self.get_app_key(client_id, trussed_fs, ctx, rng)?)
                } else {
                    None
                };
                PinData::new(
                    request.id,
                    &request.pin,
                    request.retries,
                    rng,
                    maybe_app_key.as_ref(),
                )
                .save(fs, self.location)?;
                Ok(reply::SetPin.into())
            }
            AuthRequest::DeletePin(request) => {
                let path = request.id.path();
                if fs.exists(&path, self.location) {
                    fs.remove_file(&request.id.path(), self.location)
                        .map_err(|_| Error::WriteFailed)?;
                }
                Ok(reply::DeletePin.into())
            }
            AuthRequest::DeleteAllPins(_) => {
                fs.remove_dir_all(&PathBuf::from(PIN_PATH), self.location)
                    .map_err(|_| Error::WriteFailed)?;
                Ok(reply::DeleteAllPins.into())
            }
            AuthRequest::PinRetries(request) => {
                let retries = PinData::load(fs, self.location, request.id)?.retries_left();
                Ok(reply::PinRetries { retries }.into())
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NotFound,
    ReadFailed,
    WriteFailed,
    DeserializationFailed,
    SerializationFailed,
    BadPinType,
}

impl From<Error> for trussed::error::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::NotFound => Self::NoSuchKey,
            Error::ReadFailed => Self::FilesystemReadFailure,
            Error::WriteFailed => Self::FilesystemWriteFailure,
            Error::DeserializationFailed => Self::ImplementationError,
            Error::SerializationFailed => Self::ImplementationError,
            Error::BadPinType => Self::MechanismInvalid,
        }
    }
}
