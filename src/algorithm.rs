use std::marker::PhantomData;

use wasm_bindgen::{JsCast, JsValue};
use web_sys::DomException;

#[derive(Debug, Clone, thiserror::Error)]
pub enum NonceError {
    // https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues#exceptions
    #[error("the requested nonce length exceeds 65536")]
    QuotaExceeded,
    #[error("invalid nonce size provided, expected {expected}, received {received}")]
    InvalidSize { expected: u32, received: u32 },
    #[error(transparent)]
    Generic(#[from] crate::Error),
}

impl From<wasm_bindgen::JsValue> for NonceError {
    fn from(value: wasm_bindgen::JsValue) -> Self {
        if let Some(exception) = value.dyn_ref::<web_sys::DomException>() {
            match exception.name().as_str() {
                "QuotaExceededError" => {
                    return Self::QuotaExceeded;
                }
                _ => {}
            }
        }
        Self::Generic(crate::Error::from(value))
    }
}

/// See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#exceptions
#[derive(Debug, Clone, thiserror::Error)]
pub enum EncryptionError {
    #[error("requested operation is not valid for the provided key")]
    InvalidAccess,
    #[error("operation failed for an operation-specific reason")]
    Operation,
    #[error(transparent)]
    Generic(#[from] crate::Error),
}

impl From<JsValue> for EncryptionError {
    fn from(value: JsValue) -> Self {
        if let Some(exception) = value.dyn_ref::<DomException>() {
            match exception.name().as_str() {
                "InvalidAccessError" => {
                    return Self::InvalidAccess;
                }
                "OperationError" => {
                    return Self::Operation;
                }
                _ => {}
            }
        }
        Self::Generic(crate::Error::from(value))
    }
}

/// See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt#exceptions
#[derive(Debug, Clone, thiserror::Error)]
pub enum DecryptionError {
    #[error("requested operation is not valid for the provided key")]
    InvalidAccess,
    #[error("operation failed for an operation-specific reason")]
    Operation,
    #[error(transparent)]
    Generic(#[from] crate::Error),
}

impl From<JsValue> for DecryptionError {
    fn from(value: JsValue) -> Self {
        if let Some(exception) = value.dyn_ref::<DomException>() {
            match exception.name().as_str() {
                "InvalidAccessError" => {
                    return Self::InvalidAccess;
                }
                "OperationError" => {
                    return Self::Operation;
                }
                _ => {}
            }
        }
        Self::Generic(crate::Error::from(value))
    }
}

#[derive(Debug, Clone)]
pub struct Nonce<A> {
    algo: PhantomData<A>,
    inner: js_sys::Uint8Array,
}

impl<A> AsRef<js_sys::Uint8Array> for Nonce<A> {
    fn as_ref(&self) -> &js_sys::Uint8Array {
        &self.inner
    }
}

impl<A> Nonce<A>
where
    A: Algorithm,
    A: Sized,
{
    pub fn generate() -> Result<Nonce<A>, NonceError> {
        let crypto = crate::crypto()?;
        let inner = js_sys::Uint8Array::new_with_length(A::NONCE_SIZE);
        crypto.get_random_values_with_js_u8_array(&inner)?;
        Ok(Nonce {
            algo: PhantomData,
            inner,
        })
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, NonceError> {
        let size = data.len() as u32;
        if size != A::NONCE_SIZE {
            return Err(NonceError::InvalidSize {
                expected: A::NONCE_SIZE,
                received: size,
            });
        }
        Ok(Self {
            algo: PhantomData,
            inner: js_sys::Uint8Array::from(data),
        })
    }

    pub fn iter<'a>(&'a self) -> impl Iterator<Item = u8> + 'a {
        (0..self.inner.length()).map(|idx| self.inner.get_index(idx))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        crate::array_to_vec(&self.inner)
    }
}

pub trait Algorithm: Sized {
    const NONCE_SIZE: u32;

    fn generate_nonce() -> Result<Nonce<Self>, NonceError> {
        Nonce::<Self>::generate()
    }

    fn encrypt(
        &self,
        nonce: &Nonce<Self>,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, EncryptionError>>;

    fn decrypt(
        &self,
        nonce: &Nonce<Self>,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, DecryptionError>>;
}
