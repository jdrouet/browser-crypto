use js_sys::SyntaxError;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::DomException;

use crate::algorithm::{Algorithm, DecryptionError, EncryptionError, Nonce};

const NAME: &str = "AES-GCM";

#[derive(Debug, Clone, thiserror::Error)]
pub enum ImportKeyError {
    #[error("keyUsages is empty but the unwrapped key is of type secret or private")]
    Syntax,
    #[error("invalid format or keyData not suited for that format")]
    Type,
    #[error(transparent)]
    Generic(#[from] crate::Error),
}

impl From<JsValue> for ImportKeyError {
    fn from(value: JsValue) -> Self {
        if let Some(exception) = value.dyn_ref::<DomException>() {
            if exception.name() == "SyntaxError" {
                return Self::Syntax;
            }
        }
        if value.dyn_ref::<SyntaxError>().is_some() {
            return Self::Type;
        }
        Self::Generic(crate::Error::from(value))
    }
}

#[derive(Debug, Clone)]
pub struct Aes256Gcm {
    key: web_sys::CryptoKey,
}

impl Aes256Gcm {
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
