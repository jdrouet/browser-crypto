use std::marker::PhantomData;

use wasm_bindgen::{JsCast, JsValue};
use web_sys::DomException;

/// Errors that can occur during nonce (number used once) operations.
///
/// These errors handle both Web Crypto API random generation errors and
/// nonce validation errors.
///
/// See [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues#exceptions)
#[derive(Debug, Clone, thiserror::Error)]
pub enum NonceError {
    /// Indicates that the requested nonce length exceeds the maximum allowed size.
    ///
    /// This error occurs when trying to generate a nonce larger than 65536 bytes,
    /// which is the maximum size allowed by the Web Crypto API's getRandomValues().
    /// This limit exists as a security measure to prevent excessive entropy extraction.
    ///
    /// Note: Most cryptographic algorithms use much smaller nonces
    /// (typically 12 or 16 bytes), so this error should rarely occur in practice.
    #[error("the requested nonce length exceeds 65536")]
    QuotaExceeded,
    /// Indicates that the provided nonce size doesn't match the algorithm's requirements.
    ///
    /// This error occurs when:
    /// - Creating a nonce from existing data
    /// - The provided data length doesn't match the algorithm's specified nonce size
    ///
    /// # Fields
    /// * `expected` - The nonce size required by the algorithm
    /// * `received` - The actual size of the provided nonce data
    ///
    /// For example, if AES-GCM requires a 12-byte nonce but 16 bytes were provided,
    /// this error would be returned with expected=12, received=16.
    #[error("invalid nonce size provided, expected {expected}, received {received}")]
    InvalidSize { expected: u32, received: u32 },
    /// A wrapper for other types of errors that may occur during nonce operations.
    ///
    /// This includes general Web Crypto API errors and other unexpected failures
    /// that might occur during nonce generation or handling.
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

/// Errors that can occur during encryption operations.
///
/// These errors map to the exceptions defined in the Web Crypto API specification
/// for encryption operations.
///
/// See [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#exceptions)
#[derive(Debug, Clone, thiserror::Error)]
pub enum EncryptionError {
    /// Indicates that the requested operation is not valid for the provided key.
    /// This typically occurs when:
    /// - The key doesn't support the encryption operation
    /// - The key's algorithm doesn't match the specified algorithm
    /// - The key's usages don't include "encrypt"
    #[error("requested operation is not valid for the provided key")]
    InvalidAccess,
    /// Indicates that the operation failed for an algorithm-specific reason.
    /// This can occur when:
    /// - The input data is too large
    /// - The algorithm parameters are invalid
    /// - There's an internal error in the cryptographic implementation
    #[error("operation failed for an operation-specific reason")]
    Operation,
    /// A wrapper for other types of errors that may occur during encryption
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

/// Errors that can occur during decryption operations.
///
/// These errors map to the exceptions defined in the Web Crypto API specification
/// for decryption operations.
///
/// See [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt#exceptions)
#[derive(Debug, Clone, thiserror::Error)]
pub enum DecryptionError {
    /// Indicates that the requested operation is not valid for the provided key.
    /// This typically occurs when:
    /// - The key doesn't support the decryption operation
    /// - The key's algorithm doesn't match the specified algorithm
    /// - The key's usages don't include "decrypt"
    #[error("requested operation is not valid for the provided key")]
    InvalidAccess,
    /// Indicates that the operation failed for an algorithm-specific reason.
    /// This can occur when:
    /// - The ciphertext is corrupted or malformed
    /// - The authentication tag is invalid (for authenticated encryption)
    /// - The algorithm parameters (like nonce) don't match those used for encryption
    #[error("operation failed for an operation-specific reason")]
    Operation,
    /// A wrapper for other types of errors that may occur during decryption
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

/// Nonce handling for cryptographic operations
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
    /// Generates a new random nonce
    ///
    /// # Returns
    /// Result containing generated Nonce or NonceError
    pub fn generate() -> Result<Nonce<A>, NonceError> {
        let crypto = crate::crypto()?;
        let inner = js_sys::Uint8Array::new_with_length(A::NONCE_SIZE);
        crypto.get_random_values_with_js_u8_array(&inner)?;
        Ok(Nonce {
            algo: PhantomData,
            inner,
        })
    }

    /// Creates a nonce from existing bytes
    ///
    /// # Arguments
    /// * `data` - Byte slice containing nonce data
    ///
    /// # Returns
    /// Result containing Nonce or NonceError
    ///
    /// # Errors
    /// Returns `NonceError::InvalidSize` if data length doesn't match algorithm requirements
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

    /// Returns nonce bytes as a vector
    pub fn to_vec(&self) -> Vec<u8> {
        crate::array_to_vec(&self.inner)
    }
}

/// Core cryptographic algorithm trait
pub trait Algorithm: Sized {
    /// Required nonce size in bytes for this algorithm
    const NONCE_SIZE: u32;

    /// Generates a new random nonce suitable for this algorithm
    ///
    /// # Returns
    /// Result containing the generated Nonce or a NonceError
    ///
    /// # Errors
    /// - `NonceError::QuotaExceeded` if requested length > 65536 bytes
    /// - `NonceError::InvalidSize` if nonce size doesn't match algorithm requirements
    fn generate_nonce() -> Result<Nonce<Self>, NonceError> {
        Nonce::<Self>::generate()
    }

    /// Encrypts data using this algorithm
    ///
    /// # Arguments
    /// * `nonce` - Nonce to use for encryption
    /// * `payload` - Data to encrypt
    ///
    /// # Returns
    /// Result containing encrypted bytes or an EncryptionError
    ///
    /// # Errors
    /// - `EncryptionError::InvalidAccess` if operation invalid for provided key
    /// - `EncryptionError::Operation` if encryption fails for algorithm-specific reasons
    fn encrypt(
        &self,
        nonce: &Nonce<Self>,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, EncryptionError>>;

    /// Decrypts data using this algorithm
    ///
    /// # Arguments
    /// * `nonce` - Nonce used for encryption
    /// * `payload` - Encrypted data to decrypt
    ///
    /// # Returns
    /// Result containing decrypted bytes or a DecryptionError
    ///
    /// # Errors
    /// - `DecryptionError::InvalidAccess` if operation invalid for provided key
    /// - `DecryptionError::Operation` if decryption fails for algorithm-specific reasons
    fn decrypt(
        &self,
        nonce: &Nonce<Self>,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, DecryptionError>>;
}
