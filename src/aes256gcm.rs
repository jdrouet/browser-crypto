use crate::algorithm::{Algorithm, Nonce};
use std::io::Result;

const NAME: &str = "AES-GCM";

#[derive(Debug, Clone)]
pub struct Aes256Gcm {
    key: web_sys::CryptoKey,
}

impl Aes256Gcm {
    pub async fn from_key(data: &[u8]) -> Result<Self> {
        let subtle = crate::subtle()?;

        // Convert Rust array to Uint8Array
        let js_key_data = js_sys::Uint8Array::from(data);

        // Define AES-GCM import parameters
        let algorithm = js_sys::Object::new();
        js_sys::Reflect::set(&algorithm, &"name".into(), &NAME.into())
            .map_err(crate::from_js_error)?;

        // Import the key as a CryptoKey
        let usages = js_sys::Array::new();
        usages.push(&"encrypt".into());
        usages.push(&"decrypt".into());
        let promise: js_sys::Promise = subtle
            .import_key_with_object(
                "raw",               // Import format
                &js_key_data.into(), // Key material (converted to JsValue)
                &algorithm,          // Algorithm details
                true,                // Extractable (true allows exporting later)
                &usages,             // Allowed usages
            )
            .map_err(crate::from_js_error)?;

        let key: web_sys::CryptoKey = crate::resolve(promise).await?;
        Ok(Self { key })
    }
}

impl Algorithm for Aes256Gcm {
    const NONCE_SIZE: u32 = 12;

    async fn encrypt(&self, nonce: &Nonce<Self>, payload: &[u8]) -> Result<Vec<u8>> {
        let subtle = crate::subtle()?;
        // Convert plaintext to Uint8Array
        let plaintext = js_sys::Uint8Array::from(payload);

        let params = web_sys::AesGcmParams::new(NAME, nonce.as_ref());
        let promise: js_sys::Promise = subtle
            .encrypt_with_object_and_js_u8_array(&params, &self.key, &plaintext.into())
            .map_err(crate::from_js_error)?;
        let ciphertext = crate::resolve::<js_sys::ArrayBuffer>(promise).await?;

        Ok(crate::array_to_vec(&js_sys::Uint8Array::new(&ciphertext)))
    }

    async fn decrypt(&self, nonce: &Nonce<Self>, payload: &[u8]) -> Result<Vec<u8>> {
        let subtle = crate::subtle()?;
        // Convert plaintext to Uint8Array
        let payload = js_sys::Uint8Array::from(payload);
        let params = web_sys::AesGcmParams::new(NAME, nonce.as_ref());
        let promise: js_sys::Promise = subtle
            .decrypt_with_object_and_js_u8_array(&params, &self.key, &payload.into())
            .map_err(crate::from_js_error)?;
        let clear = crate::resolve::<js_sys::ArrayBuffer>(promise).await?;

        Ok(crate::array_to_vec(&js_sys::Uint8Array::new(&clear)))
    }
}
