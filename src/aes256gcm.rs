//! AES-256-GCM encryption implementation

use js_sys::SyntaxError;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::DomException;

use crate::algorithm::{Algorithm, DecryptionError, EncryptionError, Nonce};

const NAME: &str = "AES-GCM";

/// Errors that can occur when importing cryptographic keys.
///
/// These errors map to the exceptions defined in the Web Crypto API
/// specification for key import operations.
///
/// See [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#exceptions)
#[derive(Debug, Clone, thiserror::Error)]
pub enum ImportKeyError {
    /// Indicates that the key usage array is empty for a secret or private key.
    ///
    /// This error occurs when:
    /// - No key usages are specified during import
    /// - The key type requires at least one usage to be specified
    ///
    /// Key usages typically include operations like "encrypt", "decrypt",
    /// "sign", or "verify".
    #[error("keyUsages is empty but the unwrapped key is of type secret or private")]
    Syntax,
    /// Indicates that the key data is not suitable for the specified format.
    ///
    /// This error occurs when:
    /// - The key data is malformed
    /// - The key data doesn't match the expected format
    /// - The key data is invalid for the specified algorithm
    ///
    /// For example, trying to import non-AES data as an AES key would trigger
    /// this error.
    #[error("invalid format or keyData not suited for that format")]
    Type,
    /// Indicates that an invalid key format was specified during import.
    ///
    /// This error occurs when:
    /// - The specified format (e.g., "raw", "pkcs8", "spki", "jwk") is not
    ///   supported
    /// - The specified format is not appropriate for the key type
    ///
    /// For example, trying to import a symmetric key using "spki" format would
    /// trigger this error.
    #[error("invalid key format provided")]
    InvalidKeyFormat,
    /// A wrapper for other types of errors that may occur during key import.
    ///
    /// This includes general Web Crypto API errors and other unexpected
    /// failures.
    #[error(transparent)]
    Generic(#[from] crate::Error),
}

impl From<JsValue> for ImportKeyError {
    /// Converts a JavaScript value into an ImportKeyError.
    ///
    /// Maps specific DOM exceptions to their corresponding ImportKeyError
    /// variants:
    /// - `SyntaxError` → `ImportKeyError::Syntax`
    /// - `DataError` → `ImportKeyError::InvalidKeyFormat`
    /// - JavaScript `SyntaxError` → `ImportKeyError::Type`
    /// - Other errors → `ImportKeyError::Generic`
    ///
    /// # Arguments
    /// * `value` - The JavaScript value to convert
    ///
    /// # Returns
    /// The corresponding ImportKeyError variant
    fn from(value: JsValue) -> Self {
        if let Some(exception) = value.dyn_ref::<DomException>() {
            if exception.name() == "SyntaxError" {
                return Self::Syntax;
            }
            if exception.name() == "DataError" {
                return Self::InvalidKeyFormat;
            }
        }
        if value.dyn_ref::<SyntaxError>().is_some() {
            return Self::Type;
        }
        Self::Generic(crate::Error::from(value))
    }
}

/// AES-256-GCM encryption implementation
#[derive(Debug, Clone)]
pub struct Aes256Gcm {
    key: web_sys::CryptoKey,
}

impl Aes256Gcm {
    /// Creates a new AES-256-GCM instance from a raw key.
    ///
    /// # Arguments
    /// * `data` - Raw key bytes (should be 32 bytes for AES-256)
    ///
    /// # Returns
    /// Result containing the Aes256Gcm instance or an ImportKeyError
    ///
    /// # Errors
    /// - `ImportKeyError::Syntax` if key usage array is empty
    /// - `ImportKeyError::Type` if key format/data is invalid
    /// - `ImportKeyError::InvalidKeyFormat` if provided key format is invalid
    pub async fn from_key(data: &[u8]) -> Result<Self, ImportKeyError> {
        let subtle = crate::subtle()?;

        // Convert Rust array to Uint8Array
        let js_key_data = js_sys::Uint8Array::from(data);

        // Define AES-GCM import parameters
        let algorithm = js_sys::Object::new();
        js_sys::Reflect::set(&algorithm, &"name".into(), &NAME.into())?;

        // Import the key as a CryptoKey
        let usages = js_sys::Array::new();
        usages.push(&"encrypt".into());
        usages.push(&"decrypt".into());
        let promise: js_sys::Promise = subtle.import_key_with_object(
            "raw",               // Import format
            &js_key_data.into(), // Key material (converted to JsValue)
            &algorithm,          // Algorithm details
            true,                // Extractable (true allows exporting later)
            &usages,             // Allowed usages
        )?;

        let key: web_sys::CryptoKey =
            crate::resolve::<web_sys::CryptoKey, ImportKeyError>(promise).await?;
        Ok(Self { key })
    }
}

impl Algorithm for Aes256Gcm {
    const NONCE_SIZE: u32 = 12;

    async fn encrypt(
        &self,
        nonce: &Nonce<Self>,
        payload: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let subtle = crate::subtle()?;
        // Convert plaintext to Uint8Array
        let plaintext = js_sys::Uint8Array::from(payload);

        let params = web_sys::AesGcmParams::new(NAME, nonce.as_ref());
        let promise: js_sys::Promise =
            subtle.encrypt_with_object_and_js_u8_array(&params, &self.key, &plaintext.into())?;
        let ciphertext = crate::resolve::<js_sys::ArrayBuffer, EncryptionError>(promise).await?;

        Ok(crate::array_to_vec(&js_sys::Uint8Array::new(&ciphertext)))
    }

    async fn decrypt(
        &self,
        nonce: &Nonce<Self>,
        payload: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        let subtle = crate::subtle()?;
        // Convert plaintext to Uint8Array
        let payload = js_sys::Uint8Array::from(payload);
        let params = web_sys::AesGcmParams::new(NAME, nonce.as_ref());
        let promise: js_sys::Promise =
            subtle.decrypt_with_object_and_js_u8_array(&params, &self.key, &payload.into())?;
        let clear = crate::resolve::<js_sys::ArrayBuffer, DecryptionError>(promise).await?;

        Ok(crate::array_to_vec(&js_sys::Uint8Array::new(&clear)))
    }
}
