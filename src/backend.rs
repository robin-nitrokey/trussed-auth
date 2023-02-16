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
    platform::Platform,
    serde_extensions::ExtensionImpl,
    service::ServiceResources,
    store::filestore::Filestore,
    types::{CoreContext, Location, PathBuf},
    Bytes,
};

use crate::{
    extension::{reply, AuthExtension, AuthReply, AuthRequest},
    PIN_PATH, SALT_PATH,
};
use data::PinData;

const MAX_HW_KEY_LEN: usize = 64;

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

    fn get_salt<R: CryptoRng + RngCore>(
        &self,
        trussed_filestore: &mut impl Filestore,
        rng: &mut R,
    ) -> Result<[u8; 32], Error> {
        let path = PathBuf::from(SALT_PATH);
        trussed_filestore
            .read(&path, self.location)
            .map(|d: Bytes<32>| (&**d).try_into().unwrap())
            .or_else(|_| {
                if trussed_filestore
                    .metadata(&path, self.location)
                    .or(Err(Error::ReadFailed))?
                    .is_some()
                {
                    return Err(Error::ReadFailed);
                }
                let mut salt = [0; 32];
                rng.fill_bytes(&mut salt);
                trussed_filestore
                    .write(&path, self.location, &salt)
                    .or(Err(Error::WriteFailed))
                    .and(Ok(salt))
            })
    }

    fn extract<R: CryptoRng + RngCore>(
        &mut self,
        trussed_filestore: &mut impl Filestore,
        ikm: Option<Bytes<MAX_HW_KEY_LEN>>,
        rng: &mut R,
    ) -> Result<&Hkdf<Sha256>, Error> {
        let ikm: &[u8] = ikm.as_deref().map(|i| &**i).unwrap_or(&[]);
        let salt = self.get_salt(trussed_filestore, rng)?;
        let kdf = Hkdf::new(Some(&salt), ikm);
        self.hw_key = HardwareKey::Extracted(kdf);
        match &self.hw_key {
            HardwareKey::Extracted(kdf) => Ok(kdf),
            // hw_key was just set to Extracted
            _ => unreachable!(),
        }
    }

    fn expand(kdf: &Hkdf<Sha256>, client_id: &PathBuf) -> [u8; 32] {
        let mut out = [0; 32];
        kdf.expand(client_id.as_ref().as_bytes(), &mut out).unwrap();
        out
    }

    fn generate_app_key<R: CryptoRng + RngCore>(
        &mut self,
        client_id: PathBuf,
        trussed_filestore: &mut impl Filestore,
        rng: &mut R,
    ) -> Result<[u8; 32], Error> {
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

    #[allow(unused)]
    fn get_app_key<R: CryptoRng + RngCore>(
        &mut self,
        client_id: PathBuf,
        trussed_filestore: &mut impl Filestore,
        ctx: &mut AuthContext,
        rng: &mut R,
    ) -> Result<[u8; 32], Error> {
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
    application_key: Option<[u8; 32]>,
}

impl<P: Platform> Backend<P> for AuthBackend {
    type Context = AuthContext;
}

impl<P: Platform> ExtensionImpl<AuthExtension, P> for AuthBackend {
    fn extension_request(
        &mut self,
        core_ctx: &mut CoreContext,
        _ctx: &mut AuthContext,
        request: &AuthRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<AuthReply> {
        let fs = &mut resources.filestore(core_ctx);
        match request {
            AuthRequest::HasPin(request) => {
                let has_pin = fs.exists(&request.id.path(), self.location);
                Ok(reply::HasPin { has_pin }.into())
            }
            AuthRequest::CheckPin(request) => {
                let success = PinData::load(fs, self.location, request.id)?.write(
                    fs,
                    self.location,
                    |data| data.check_pin(&request.pin),
                )?;
                Ok(reply::CheckPin { success }.into())
            }
            AuthRequest::GetPinKey(_request) => {
                todo!()
            }
            AuthRequest::SetPin(request) => {
                let mut rng = resources.rng().map_err(|_| Error::RngFailed)?;
                PinData::new(request.id, &request.pin, request.retries, &mut rng)
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
    RngFailed,
    ReadFailed,
    WriteFailed,
    DeserializationFailed,
    SerializationFailed,
}

impl From<Error> for trussed::error::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::NotFound => Self::NoSuchKey,
            Error::RngFailed => Self::EntropyMalfunction,
            Error::ReadFailed => Self::FilesystemReadFailure,
            Error::WriteFailed => Self::FilesystemWriteFailure,
            Error::DeserializationFailed => Self::ImplementationError,
            Error::SerializationFailed => Self::ImplementationError,
        }
    }
}
