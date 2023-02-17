// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use core::ops::Deref;

use chacha20poly1305::ChaCha8Poly1305;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use trussed::{
    platform::{CryptoRng, RngCore},
    store::filestore::Filestore,
    types::Location,
};

use super::Error;
use crate::{Pin, PinId, MAX_PIN_LENGTH};

const SIZE: usize = 256;
const CHACHA_TAG_LEN: usize = 16;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
const KEY_LEN: usize = 32;

pub(crate) type Salt = ByteArray<SALT_LEN>;
pub(crate) type Hash = ByteArray<HASH_LEN>;
pub(crate) type ChaChaTag = ByteArray<CHACHA_TAG_LEN>;
pub(crate) type Key = ByteArray<KEY_LEN>;

#[derive(Debug, Deserialize, Serialize)]
enum KeyOrHash {
    Key { wrapped_key: Key, tag: ChaChaTag },
    Hash(Hash),
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PinData {
    #[serde(skip)]
    id: PinId,
    retries: Option<Retries>,
    salt: Salt,
    data: KeyOrHash,
}

impl PinData {
    /// An application_key of `None` means that the pin should only be salted/hashed
    /// `Some` means that it should instead be used to wrap a 32 bytes encryption key
    pub fn new<R>(
        id: PinId,
        pin: &Pin,
        retries: Option<u8>,
        rng: &mut R,
        application_key: Option<&Key>,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut salt = Salt::default();
        rng.fill_bytes(salt.as_mut());
        let data = application_key
            .map(|k| {
                use chacha20poly1305::{AeadInPlace, KeyInit};
                let mut key = Key::default();
                rng.fill_bytes(&mut *key);
                let pin_key = derive_key(id, pin, &salt, k);
                let aead = ChaCha8Poly1305::new((&*pin_key).into());
                // The pin key is only ever used to once to wrap a key. Nonce reuse is not a concern
                // Because the salt is also used in the key derivation process, PIN reuse across PINs will still lead to different keys
                let nonce = Default::default();
                let tag: [u8; CHACHA_TAG_LEN] = aead
                    .encrypt_in_place_detached(&nonce, &[u8::from(id)], &mut *key)
                    .expect("Wrapping the key should always work")
                    .into();

                KeyOrHash::Key {
                    wrapped_key: key,
                    tag: tag.into(),
                }
            })
            .unwrap_or_else(|| KeyOrHash::Hash(hash(id, pin, &salt)));
        Self {
            id,
            retries: retries.map(From::from),
            salt,
            data,
        }
    }

    pub fn load<S: Filestore>(fs: &mut S, location: Location, id: PinId) -> Result<Self, Error> {
        let path = id.path();
        if !fs.exists(&path, location) {
            return Err(Error::NotFound);
        }
        let data = fs
            .read::<SIZE>(&path, location)
            .map_err(|_| Error::ReadFailed)?;
        let mut data: Self =
            trussed::cbor_deserialize(&data).map_err(|_| Error::DeserializationFailed)?;
        data.id = id;
        Ok(data)
    }

    pub fn save<S: Filestore>(&self, fs: &mut S, location: Location) -> Result<(), Error> {
        let data = trussed::cbor_serialize_bytes::<_, SIZE>(self)
            .map_err(|_| Error::SerializationFailed)?;
        fs.write(&self.id.path(), location, &data)
            .map_err(|_| Error::WriteFailed)
    }

    pub fn retries_left(&self) -> Option<u8> {
        self.retries.map(|retries| retries.left)
    }

    pub fn is_blocked(&self) -> bool {
        if let Some(retries) = self.retries {
            retries.left == 0
        } else {
            false
        }
    }

    pub fn write<S, F, R>(&mut self, fs: &mut S, location: Location, f: F) -> Result<R, Error>
    where
        S: Filestore,
        F: FnOnce(&mut PinDataMut<'_>) -> R,
    {
        let mut data = PinDataMut::new(self);
        let result = f(&mut data);
        if data.modified {
            self.save(fs, location)?;
        }
        Ok(result)
    }
}

pub(crate) struct PinDataMut<'a> {
    data: &'a mut PinData,
    modified: bool,
}

enum CheckResult {
    Validated,
    Derived(Key),
    Failed,
}

impl CheckResult {
    fn is_success(&self) -> bool {
        matches!(self, CheckResult::Validated | CheckResult::Derived(_))
    }
}

impl<'a> PinDataMut<'a> {
    fn new(data: &'a mut PinData) -> Self {
        Self {
            data,
            modified: false,
        }
    }

    fn check_or_unwrap(
        &mut self,
        pin: &Pin,
        application_key: impl FnOnce() -> Result<Key, Error>,
    ) -> Result<CheckResult, Error> {
        if self.is_blocked() {
            return Ok(CheckResult::Failed);
        }
        let res = match self.data.data {
            KeyOrHash::Hash(h) => {
                if hash(self.id, pin, &self.salt).ct_eq(&*h).into() {
                    CheckResult::Validated
                } else {
                    CheckResult::Failed
                }
            }
            KeyOrHash::Key { wrapped_key, tag } => {
                if let Some(k) = self.unwrap_key(pin, &application_key()?, wrapped_key, &tag) {
                    CheckResult::Derived(k)
                } else {
                    CheckResult::Failed
                }
            }
        };
        if let Some(retries) = &mut self.data.retries {
            if res.is_success() {
                if retries.reset() {
                    self.modified = true;
                }
            } else {
                retries.decrement();
                self.modified = true;
            }
        }
        Ok(res)
    }

    pub fn check_pin(
        &mut self,
        pin: &Pin,
        application_key: impl FnOnce() -> Result<Key, Error>,
    ) -> Result<bool, Error> {
        self.check_or_unwrap(pin, application_key)
            .map(|res| res.is_success())
    }

    #[must_use]
    fn unwrap_key(
        &self,
        pin: &Pin,
        application_key: &Key,
        mut wrapped_key: Key,
        tag: &ChaChaTag,
    ) -> Option<Key> {
        use chacha20poly1305::{AeadInPlace, KeyInit};

        let pin_key = derive_key(self.id, pin, &self.salt, application_key);
        let aead = ChaCha8Poly1305::new((&*pin_key).into());
        // The pin key is only ever used to once to wrap a key. Nonce reuse is not a concern
        // Because the salt is also used in the key derivation process, PIN reuse across PINs will still lead to different keys
        let nonce = Default::default();
        aead.decrypt_in_place_detached(
            &nonce,
            &[u8::from(self.data.id)],
            &mut *wrapped_key,
            (&**tag).into(),
        )
        .ok()
        .and(Some(wrapped_key))
    }

    #[must_use]
    pub fn get_pin_key(&mut self, pin: &Pin, application_key: &Key) -> Result<Option<Key>, Error> {
        match self.check_or_unwrap(pin, || Ok(*application_key))? {
            CheckResult::Validated => Err(Error::BadPinType),
            CheckResult::Derived(k) => Ok(Some(k)),
            CheckResult::Failed => Ok(None),
        }
    }
}

impl Deref for PinDataMut<'_> {
    type Target = PinData;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct Retries {
    max: u8,
    left: u8,
}

impl Retries {
    fn decrement(&mut self) {
        self.left = self.left.saturating_sub(1);
    }

    fn reset(&mut self) -> bool {
        if self.left == self.max {
            false
        } else {
            self.left = self.max;
            true
        }
    }
}

impl From<u8> for Retries {
    fn from(retries: u8) -> Self {
        Self {
            max: retries,
            left: retries,
        }
    }
}

fn hash(id: PinId, pin: &Pin, salt: &Salt) -> Hash {
    let mut digest = Sha256::new();
    digest.update([u8::from(id)]);
    digest.update([pin_len(pin)]);
    digest.update(pin);
    digest.update(*salt);
    Hash::new(digest.finalize().into())
}

fn derive_key(id: PinId, pin: &Pin, salt: &Salt, application_key: &[u8; 32]) -> Hash {
    let mut hmac = Hmac::<Sha256>::new_from_slice(application_key).unwrap();
    hmac.update(&[u8::from(id)]);
    hmac.update(&[pin_len(pin)]);
    hmac.update(pin);
    hmac.update(&**salt);
    let tmp: [_; HASH_LEN] = hmac.finalize().into_bytes().into();
    tmp.into()
}

fn pin_len(pin: &Pin) -> u8 {
    const _: () = assert!(MAX_PIN_LENGTH <= u8::MAX as usize);
    pin.len() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_data_size() {
        let data = PinData {
            id: PinId::from(u8::MAX),
            retries: Some(Retries {
                max: u8::MAX,
                left: u8::MAX,
            }),
            salt: [u8::MAX; SALT_LEN].into(),
            data: KeyOrHash::Hash([u8::MAX; HASH_LEN].into()),
        };
        let serialized = trussed::cbor_serialize_bytes::<_, 1024>(&data).unwrap();
        assert!(serialized.len() <= SIZE);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_salt_size() {
        // We allow one byte overhead for byte array serialization
        let salt = Salt::from([u8::MAX; SALT_LEN]);
        let serialized = trussed::cbor_serialize_bytes::<_, 1024>(&salt).unwrap();
        assert!(serialized.len() <= SALT_LEN + 1, "{}", serialized.len());
    }
}
